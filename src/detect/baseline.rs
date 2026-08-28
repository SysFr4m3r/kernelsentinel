//! Per-host baselining. The recurring false positive across every milestone has
//! the same shape: a signal fires on a process whose (signal, executable) pair
//! is routine on this host -- privilege_escalation on /usr/bin/sudo, module_load
//! by systemd-modules-load, suid_create by the package manager.
//!
//! A baseline learns those pairs from a known-clean observation period, then the
//! engine downweights a signal whose pair is known-normal while leaving novel
//! behavior at full score. A known pair is *reduced, not erased*, so a routine
//! signal appearing inside a genuinely novel chain still contributes a little.
//!
//! # Why membership alone is not enough
//!
//! Treating "present in the baseline" as proof of normal has two failure modes,
//! and both are exploitable rather than theoretical:
//!
//! - **Poisoning.** Anything that happens once during the learning window is
//!   learned as normal, forever. An attacker already resident on the host when
//!   the operator records a "clean" capture gets their own behavior whitelisted,
//!   and a single burst of the same action looks identical to a habit.
//! - **Staleness.** Hosts get repurposed, packages move, admins change. A
//!   baseline learned a year ago keeps suppressing at full strength with no
//!   signal that its evidence has expired.
//!
//! So an entry does not carry a verdict, it carries *evidence*, and the
//! suppression it earns is proportional to that evidence:
//!
//! - **Support** -- how many times the pair was seen. One sighting is not a habit.
//! - **Recurrence** -- how much of the learning window it spanned. Behavior that
//!   recurs across the whole observation is normal; ten thousand occurrences
//!   inside three seconds is one burst, and can never reach full confidence.
//! - **Freshness** -- how long ago the baseline was learned. Confidence decays
//!   with age and reaches zero at [`STALE_DAYS`], after which the baseline
//!   suppresses nothing at all.
//!
//! Every one of those degrades *toward alerting*. A baseline that cannot justify
//! itself gets out of the way rather than quietly hiding things.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Current on-disk format. v1 stored a bare count with no timestamps, so
/// neither recurrence nor age can be recovered from one; see [`Baseline::load`].
pub const FORMAT_VERSION: u32 = 2;

/// The score a fully-confident known-normal pair keeps. Small but non-zero on
/// purpose: routine behavior inside a novel chain still counts for something.
/// This is the *floor* -- less confidence means less suppression, never more.
pub const KNOWN_FACTOR: f64 = 0.1;

/// Observations for full support. Chosen low because independent occurrences
/// spread across a real learning window are convincing quickly, and because the
/// curve is logarithmic: the gap between one sighting and three matters far more
/// than the gap between thirty and three hundred.
const SUPPORT_FULL: f64 = 8.0;

/// Confidence a pair earns when every observation fell at the same instant.
/// A burst is one event repeated, not repeated evidence, so it is capped here
/// no matter how many times it occurred.
const BURST_RECURRENCE: f64 = 0.5;

/// A baseline is trusted at full strength for this long.
pub const FRESH_DAYS: f64 = 14.0;
/// ...then decays linearly to nothing here. Past this it suppresses nothing.
pub const STALE_DAYS: f64 = 90.0;

/// Confidence at which an entry is worth calling "strong": it removes roughly
/// two thirds of a signal's score. Anything below still helps, but an operator
/// told only that their baseline holds 42 patterns deserves to know how many of
/// them are actually doing the job.
const STRONG_CONFIDENCE: f64 = 0.75;

const MS_PER_DAY: f64 = 86_400_000.0;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One learned (signal, exe) pair and the evidence behind it. Timestamps are
/// the kernel's boot-relative nanoseconds, which is all that recurrence needs:
/// it is a ratio against the learning window, not a wall-clock time.
#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub signal: String,
    pub exe: String,
    pub count: u64,
    /// Absent in v1 baselines, where both read as 0 and recurrence is unknown.
    #[serde(default)]
    pub first_ns: u64,
    #[serde(default)]
    pub last_ns: u64,
}

#[derive(Clone, Copy, Default)]
struct Stat {
    count: u64,
    first_ns: u64,
    last_ns: u64,
}

impl Stat {
    fn span_ns(&self) -> u64 {
        self.last_ns.saturating_sub(self.first_ns)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    #[serde(default)]
    pub events_observed: u64,
    /// Wall-clock epoch ms when this baseline was learned. 0 means unknown,
    /// which only happens for a v1 file: age cannot be evaluated, so it is not
    /// held against it.
    #[serde(default)]
    pub learned_at_ms: u64,
    /// Span of the learning capture in nanoseconds, the denominator for
    /// recurrence. 0 means unknown or instantaneous; either way no entry can
    /// demonstrate that it recurred.
    #[serde(default)]
    pub window_ns: u64,
    pub entries: Vec<Entry>,

    /// Rebuilt on load from `entries`; not serialized.
    #[serde(skip)]
    index: HashMap<(String, String), Stat>,
    /// Bounds of the learning window as it is being built. 0 means unset --
    /// `note_event` rejects a zero timestamp, so the sentinel is unambiguous,
    /// and a deserialized baseline (where these come back as 0) extended with
    /// further observations starts its window from the first of them rather
    /// than from the epoch.
    #[serde(skip)]
    window_lo: u64,
    #[serde(skip)]
    window_hi: u64,
    /// The moment age is measured against. Set to "now" on load, and to the
    /// learning time for an in-memory baseline, which is fresh by construction.
    #[serde(skip)]
    evaluated_at_ms: u64,
}

impl Default for Baseline {
    fn default() -> Self {
        Self::new()
    }
}

impl Baseline {
    pub fn new() -> Self {
        let now = now_ms();
        Self {
            version: FORMAT_VERSION,
            events_observed: 0,
            learned_at_ms: now,
            window_ns: 0,
            entries: Vec::new(),
            index: HashMap::new(),
            window_lo: 0,
            window_hi: 0,
            evaluated_at_ms: now,
        }
    }

    /// Extend the learning window to include this event. Call for *every* event
    /// in the capture, not only the ones that produce signals: the window is how
    /// long the host was observed, and a pair seen once in a day-long capture
    /// must not look like a pair seen once in a one-second one.
    pub fn note_event(&mut self, ts_ns: u64) {
        if ts_ns == 0 {
            return;
        }
        self.window_lo = if self.window_lo == 0 {
            ts_ns
        } else {
            self.window_lo.min(ts_ns)
        };
        self.window_hi = self.window_hi.max(ts_ns);
        self.window_ns = self.window_hi.saturating_sub(self.window_lo);
    }

    /// Record one observed (signal, exe) pair during learning.
    pub fn observe(&mut self, signal: &str, exe: &str, ts_ns: u64) {
        // An empty exe (unresolved) is not a useful baseline key.
        if exe.is_empty() {
            return;
        }
        self.note_event(ts_ns);
        let stat = self
            .index
            .entry((signal.to_string(), exe.to_string()))
            .or_default();
        if stat.count == 0 {
            stat.first_ns = ts_ns;
            stat.last_ns = ts_ns;
        } else {
            stat.first_ns = stat.first_ns.min(ts_ns);
            stat.last_ns = stat.last_ns.max(ts_ns);
        }
        stat.count += 1;
    }

    /// Is this (signal, exe) pair present in the learned set at all? Presence is
    /// not a verdict -- see [`Baseline::confidence`] for how much it is worth.
    pub fn known(&self, signal: &str, exe: &str) -> bool {
        self.stat(signal, exe).is_some()
    }

    fn stat(&self, signal: &str, exe: &str) -> Option<Stat> {
        self.index
            .get(&(signal.to_string(), exe.to_string()))
            .copied()
    }

    /// Evidence that this pair is normal on this host, in 0.0..=1.0, already
    /// discounted for the baseline's age. 0.0 for an unknown pair.
    pub fn confidence(&self, signal: &str, exe: &str) -> f64 {
        let Some(stat) = self.stat(signal, exe) else {
            return 0.0;
        };
        self.evidence(&stat) * self.freshness()
    }

    /// Support x recurrence, before age. Kept separate so the reason a pair is
    /// weak -- thin evidence or an old baseline -- stays distinguishable.
    fn evidence(&self, stat: &Stat) -> f64 {
        let support = ((stat.count as f64).ln_1p() / SUPPORT_FULL.ln_1p()).clamp(0.0, 1.0);
        let spread = if self.window_ns == 0 {
            // Unknown window (a v1 file) or an instantaneous capture. Neither
            // can demonstrate that anything recurred, so every entry falls back
            // to the burst floor instead of being assumed to have earned more.
            0.0
        } else {
            (stat.span_ns() as f64 / self.window_ns as f64).clamp(0.0, 1.0)
        };
        let recurrence = BURST_RECURRENCE + (1.0 - BURST_RECURRENCE) * spread;
        support * recurrence
    }

    /// The fraction of its learned strength this baseline still carries:
    /// 1.0 for the first [`FRESH_DAYS`], then linear to 0.0 at [`STALE_DAYS`].
    ///
    /// A v1 baseline records no learning time. Age is then unknown, and unknown
    /// is not treated as old -- it would silently disable a baseline the
    /// operator believes is working. `load` warns about that case instead.
    pub fn freshness(&self) -> f64 {
        let Some(days) = self.age_days() else {
            return 1.0;
        };
        if days <= FRESH_DAYS {
            1.0
        } else if days >= STALE_DAYS {
            0.0
        } else {
            1.0 - (days - FRESH_DAYS) / (STALE_DAYS - FRESH_DAYS)
        }
    }

    /// Age in days, or None when the baseline does not record when it was built.
    pub fn age_days(&self) -> Option<f64> {
        if self.learned_at_ms == 0 {
            return None;
        }
        let now = if self.evaluated_at_ms == 0 {
            now_ms()
        } else {
            self.evaluated_at_ms
        };
        Some(now.saturating_sub(self.learned_at_ms) as f64 / MS_PER_DAY)
    }

    pub fn is_expired(&self) -> bool {
        self.age_days().is_some_and(|d| d >= STALE_DAYS)
    }

    /// Pin the moment age is measured against. Callers that need a deterministic
    /// result -- replaying a capture, tests -- set it explicitly rather than
    /// letting the wall clock leak into the outcome.
    pub fn evaluate_at(&mut self, now_ms: u64) {
        self.evaluated_at_ms = now_ms;
    }

    /// The multiplier to apply to a signal's score. 1.0 leaves it untouched;
    /// [`KNOWN_FACTOR`] is the strongest suppression a pair can ever earn.
    pub fn factor(&self, signal: &str, exe: &str) -> f64 {
        1.0 - self.confidence(signal, exe) * (1.0 - KNOWN_FACTOR)
    }

    /// How many times a pair was seen, for explaining a suppression.
    pub fn count(&self, signal: &str, exe: &str) -> u64 {
        self.stat(signal, exe).map(|s| s.count).unwrap_or(0)
    }

    /// Entries carrying enough evidence to suppress most of a signal's score.
    /// The complement is not useless -- it is the part of the baseline the
    /// operator should know is doing almost nothing.
    pub fn strong(&self) -> usize {
        self.index
            .values()
            .filter(|s| self.evidence(s) * self.freshness() >= STRONG_CONFIDENCE)
            .count()
    }

    /// One line for the startup banner: what this baseline is worth, in the
    /// terms that decide it. An operator who is told only "42 known patterns"
    /// has no way to find out that all 42 were seen once, or that the file is
    /// four months old.
    pub fn summary(&self) -> String {
        let mut s = format!("{} patterns ({} strong)", self.len(), self.strong());
        if self.window_ns > 0 {
            s.push_str(&format!(
                ", {} learning window",
                human_dur(self.window_ns / 1_000_000_000)
            ));
        }
        match self.age_days() {
            None => s.push_str(", age unknown (v1 format -- re-learn)"),
            Some(d) if self.is_expired() => s.push_str(&format!(
                ", learned {d:.0}d ago: EXPIRED past {STALE_DAYS:.0}d, suppressing nothing -- re-learn"
            )),
            Some(d) => {
                s.push_str(&format!(", learned {d:.0}d ago"));
                let f = self.freshness();
                if f < 1.0 {
                    s.push_str(&format!(" ({:.0}% strength)", f * 100.0));
                }
            }
        }
        s
    }

    /// Fold the index into the serializable `entries` before saving.
    fn flatten(&mut self) {
        self.entries = self
            .index
            .iter()
            .map(|((signal, exe), stat)| Entry {
                signal: signal.clone(),
                exe: exe.clone(),
                count: stat.count,
                first_ns: stat.first_ns,
                last_ns: stat.last_ns,
            })
            .collect();
        self.entries
            .sort_by(|a, b| a.signal.cmp(&b.signal).then_with(|| a.exe.cmp(&b.exe)));
    }

    /// Rebuild the lookup index after deserializing.
    fn reindex(&mut self) {
        self.index = self
            .entries
            .iter()
            .map(|e| {
                (
                    (e.signal.clone(), e.exe.clone()),
                    Stat {
                        count: e.count,
                        first_ns: e.first_ns,
                        last_ns: e.last_ns,
                    },
                )
            })
            .collect();
    }

    pub fn save(&mut self, path: &str) -> std::io::Result<()> {
        self.flatten();
        self.version = FORMAT_VERSION;
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, json)
    }

    /// Load a baseline and age it against the current wall clock.
    ///
    /// A v1 file loads and works: its counts are real, only the timestamps are
    /// missing. Every entry then reads as a single burst of unknown age, which
    /// is the honest reading of a record that never stored when anything
    /// happened -- weaker than it was under v1's membership test, and the
    /// warning says so rather than letting the operator discover it from a
    /// changed alert volume.
    pub fn load(path: &str) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut b: Baseline = serde_json::from_str(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        b.reindex();
        b.evaluated_at_ms = now_ms();
        Ok(b)
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

fn human_dur(secs: u64) -> String {
    match secs {
        s if s >= 86_400 => format!("{:.1}d", s as f64 / 86_400.0),
        s if s >= 3_600 => format!("{:.1}h", s as f64 / 3_600.0),
        s if s >= 60 => format!("{:.0}m", s as f64 / 60.0),
        s => format!("{s}s"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR_NS: u64 = 3_600_000_000_000;

    /// A pair seen many times, spread across the whole learning window.
    fn well_evidenced() -> Baseline {
        let mut b = Baseline::new();
        for i in 0..12u64 {
            b.observe("privilege_escalation", "/usr/bin/sudo", i * HOUR_NS);
        }
        b
    }

    #[test]
    fn known_after_observed() {
        let mut b = Baseline::new();
        b.observe("privilege_escalation", "/usr/bin/sudo", 1);
        assert!(b.known("privilege_escalation", "/usr/bin/sudo"));
        assert!(!b.known("privilege_escalation", "/tmp/evil"));
        assert!(!b.known("suid_create", "/usr/bin/sudo"));
    }

    #[test]
    fn empty_exe_is_not_learned() {
        let mut b = Baseline::new();
        b.observe("module_load", "", 1);
        assert!(!b.known("module_load", ""));
    }

    #[test]
    fn unknown_pair_is_never_suppressed() {
        let b = well_evidenced();
        assert_eq!(b.confidence("suid_create", "/tmp/.x"), 0.0);
        assert_eq!(b.factor("suid_create", "/tmp/.x"), 1.0);
    }

    #[test]
    fn well_evidenced_pair_reaches_full_suppression() {
        let b = well_evidenced();
        assert!(
            b.confidence("privilege_escalation", "/usr/bin/sudo") > 0.95,
            "12 sightings across the whole window should be convincing"
        );
        assert!((b.factor("privilege_escalation", "/usr/bin/sudo") - KNOWN_FACTOR).abs() < 0.05);
    }

    /// The poisoning case: an attacker resident during the learning window.
    /// Under the old membership test one sighting whitelisted them outright.
    #[test]
    fn a_single_sighting_barely_suppresses() {
        let mut b = Baseline::new();
        for i in 0..12u64 {
            b.observe("privilege_escalation", "/usr/bin/sudo", i * HOUR_NS);
        }
        b.observe("suid_create", "/tmp/.x", 3 * HOUR_NS);

        assert!(b.known("suid_create", "/tmp/.x"), "it is in the set");
        assert!(
            b.factor("suid_create", "/tmp/.x") > 0.8,
            "but one sighting must keep most of the score: {}",
            b.factor("suid_create", "/tmp/.x")
        );
    }

    /// The other poisoning shape: volume without duration. Looping a payload
    /// during learning must not buy the trust that a habit earns.
    #[test]
    fn a_burst_cannot_reach_full_confidence() {
        let mut b = Baseline::new();
        b.note_event(0);
        b.note_event(12 * HOUR_NS);
        for _ in 0..10_000 {
            b.observe("suid_create", "/tmp/.x", 5 * HOUR_NS);
        }
        let burst = b.confidence("suid_create", "/tmp/.x");
        assert!(
            burst <= BURST_RECURRENCE + f64::EPSILON,
            "10k occurrences at one instant reached {burst}"
        );

        // The same count spread across the window is worth strictly more.
        let mut spread = Baseline::new();
        for i in 0..10_000u64 {
            spread.observe("suid_create", "/tmp/.x", i * (12 * HOUR_NS / 10_000));
        }
        assert!(spread.confidence("suid_create", "/tmp/.x") > burst);
    }

    #[test]
    fn confidence_decays_with_age_and_expires() {
        let mut b = well_evidenced();
        let learned = b.learned_at_ms;
        let day = MS_PER_DAY as u64;

        b.evaluate_at(learned + 7 * day);
        assert_eq!(b.freshness(), 1.0, "inside the fresh window");
        let fresh = b.confidence("privilege_escalation", "/usr/bin/sudo");

        b.evaluate_at(learned + 52 * day);
        let middle = b.confidence("privilege_escalation", "/usr/bin/sudo");
        assert!(middle < fresh && middle > 0.0, "decaying, not gone");

        b.evaluate_at(learned + 120 * day);
        assert!(b.is_expired());
        assert_eq!(b.confidence("privilege_escalation", "/usr/bin/sudo"), 0.0);
        assert_eq!(
            b.factor("privilege_escalation", "/usr/bin/sudo"),
            1.0,
            "an expired baseline must suppress nothing, not suppress silently"
        );
    }

    /// Decay has to fail toward alerting. Any other direction means an
    /// unmaintained baseline quietly hides more over time.
    #[test]
    fn factor_never_drops_below_the_floor_or_above_one() {
        let mut b = well_evidenced();
        let learned = b.learned_at_ms;
        for d in [0u64, 1, 14, 15, 45, 89, 90, 400] {
            b.evaluate_at(learned + d * MS_PER_DAY as u64);
            let f = b.factor("privilege_escalation", "/usr/bin/sudo");
            assert!(
                (KNOWN_FACTOR - 1e-9..=1.0).contains(&f),
                "factor {f} out of range at {d}d"
            );
        }
    }

    #[test]
    fn roundtrips_through_json() {
        let mut b = well_evidenced();
        let path = std::env::temp_dir().join("ks-baseline-test.json");
        let path = path.to_str().unwrap();
        b.save(path).unwrap();
        let loaded = Baseline::load(path).unwrap();
        assert!(loaded.known("privilege_escalation", "/usr/bin/sudo"));
        assert_eq!(loaded.window_ns, b.window_ns);
        assert!(
            (loaded.confidence("privilege_escalation", "/usr/bin/sudo")
                - b.confidence("privilege_escalation", "/usr/bin/sudo"))
            .abs()
                < 0.01,
            "evidence must survive the round trip"
        );
    }

    /// v1 files predate every timestamp. They must still load and still work,
    /// just at the strength a record with no timing can justify.
    #[test]
    fn v1_baseline_loads_without_timestamps() {
        let v1 = r#"{"version":1,"events_observed":900,
            "entries":[{"signal":"privilege_escalation","exe":"/usr/bin/sudo","count":40}]}"#;
        let path = std::env::temp_dir().join("ks-baseline-v1.json");
        std::fs::write(&path, v1).unwrap();
        let b = Baseline::load(path.to_str().unwrap()).unwrap();

        assert!(b.known("privilege_escalation", "/usr/bin/sudo"));
        assert_eq!(b.age_days(), None, "a v1 file records no learning time");
        assert_eq!(b.freshness(), 1.0, "unknown age must not read as expired");
        let c = b.confidence("privilege_escalation", "/usr/bin/sudo");
        assert!(
            (0.0..=BURST_RECURRENCE + f64::EPSILON).contains(&c),
            "no window means no demonstrated recurrence, got {c}"
        );
        assert!(b.summary().contains("re-learn"));
    }

    #[test]
    fn summary_names_the_reason_it_is_weak() {
        let mut b = well_evidenced();
        let learned = b.learned_at_ms;
        b.evaluate_at(learned + 200 * MS_PER_DAY as u64);
        let s = b.summary();
        assert!(s.contains("EXPIRED"), "{s}");
        assert!(s.contains("re-learn"), "{s}");
    }
}
