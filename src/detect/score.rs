//! Risk scoring. The design goal is explainability: every number an alert
//! shows must decompose into named contributions, because a score nobody can
//! explain is a score nobody acts on.

use super::signal::Signal;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(score: u32) -> Self {
        match score {
            0..=24 => Severity::Info,
            25..=49 => Severity::Low,
            50..=74 => Severity::Medium,
            75..=89 => Severity::High,
            _ => Severity::Critical,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// The result of scoring a lineage: a final number plus the breakdown that
/// produced it, so the alert can print exactly why.
pub struct Score {
    pub total: u32,
    pub base: u32,
    pub chain_bonus: u32,
    pub context_mult: f64,
    pub context_note: Option<String>,
    pub severity: Severity,
}

/// How far apart two signals may be and still be read as one operation.
///
/// Ten minutes. Long enough to cover an attacker working at a keyboard --
/// escalate, look around, take the hashes -- and far short of the 75-minute
/// median gap that was turning one `sudo apt upgrade` into 93 critical
/// incidents.
const CHAIN_WINDOW_NS: u64 = 600 * 1_000_000_000;

/// The behaviour a signal id belongs to.
///
/// Scoring has always treated the same id firing twice as one reason to worry
/// rather than two. Ids are finer-grained than behaviours, though, and the
/// difference produced a false positive: a package upgrade that writes
/// `/etc/pam.d` and `/etc/profile.d` emits `cred_config_write` (35) and
/// `persistence_write` (30), two distinct ids, and the chain bonus turned that
/// into an **82 — HIGH** for `apt upgrade`. Measured, not predicted; the
/// scenario is `tests/noise/package_upgrade_login_files.sh`.
///
/// Writing two files of the same kind is one behaviour observed twice, not two
/// independent lines of evidence. What the chain bonus is for is *diverse*
/// evidence — a write, then an escalation, then a shell — and grouping by
/// behaviour is what makes it mean that.
///
/// Ids not named here are their own family, so a new detection defaults to
/// counting on its own rather than being silently folded into something else.
fn family(id: &str) -> &str {
    match id {
        // Writes to a watched file. Which file changes the score, not the
        // nature of the act.
        "ldso_preload_write"
        | "authorized_keys_write"
        | "persistence_write"
        | "cred_config_write"
        | "sensitive_write" => "watched_write",
        // Reading a credential store, whichever one it is.
        "credential_store_read" | "ssh_private_key_read" => "credential_read",
        // Reaching into another process.
        "ptrace_attach" | "cross_uid_proc_read" => "process_access",
        other => other,
    }
}

/// Score a set of signals drawn from one lineage.
///
/// - base: the signals sum.
/// - chain bonus: distinct detections in one causal chain matter more than the
///   same score spread across unrelated processes, so add half the largest
///   signal for each detection beyond the first. memfd(45)+uid0(40) -> 94,
///   not 85.
/// - context: a lineage rooted at a network-facing daemon, or inside a
///   container, is more suspicious for the same actions.
pub fn score(signals: &[Signal], ctx: Context) -> Score {
    if signals.is_empty() {
        return Score {
            total: 0,
            base: 0,
            chain_bonus: 0,
            context_mult: 1.0,
            context_note: None,
            severity: Severity::Info,
        };
    }

    // Only signals near each other in time are scored together.
    //
    // A chain bonus is a claim about causation: these things happened as one
    // operation. Shared lineage alone does not establish that. A `sudo` at the
    // start of an admin session stays in the ancestry of everything that
    // session later does, so without a window every routine action beneath it
    // inherits an escalation as "a second kind of evidence".
    //
    // Measured, in a 1.4-hour capture containing one `apt upgrade`: 93 critical
    // incidents paired `privilege_escalation` with `credential_store_read`, and
    // the median gap between the two was **4,494 seconds**. One of the 93 was
    // within fifteen minutes. The tool was reporting a `sudo` from 75 minutes
    // earlier as corroboration for `debconf` reading /etc/shadow now.
    //
    // Older signals stay in the incident and stay visible to an analyst; they
    // simply stop contributing to the number. The evasion is stated in
    // docs/DETECTIONS.md: an attacker who waits out the window splits one
    // operation into separately-unremarkable halves. That is a real cost, and
    // smaller than alerting on every package upgrade.
    let newest = signals.iter().map(|s| s.ts_ns).max().unwrap_or(0);
    let recent: Vec<&Signal> = signals
        .iter()
        .filter(|s| newest.saturating_sub(s.ts_ns) <= CHAIN_WINDOW_NS)
        .collect();
    let signals: &[&Signal] = &recent;

    // Base is the sum of the highest score per *family*, not per signal. The
    // same behaviour firing more than once in one lineage -- two sudos each
    // escalating, or one process writing both a PAM file and a profile script
    // -- is one reason to worry, not N. This keeps `base` consistent with the
    // distinct-family chain bonus below.
    use std::collections::HashMap;
    let mut per_family: HashMap<&str, u32> = HashMap::new();
    for s in signals {
        let e = per_family.entry(family(s.id)).or_insert(0);
        *e = (*e).max(s.score);
    }
    let base: u32 = per_family.values().sum();
    let distinct = per_family.len() as u32;

    let max = per_family.values().copied().max().unwrap_or(0);
    let chain_bonus = if distinct > 1 {
        (distinct - 1) * max / 2
    } else {
        0
    };

    let (context_mult, context_note) = ctx.multiplier();

    let total = (((base + chain_bonus) as f64) * context_mult).round() as u32;
    let total = total.min(100);

    Score {
        total,
        base,
        chain_bonus,
        context_mult,
        context_note,
        severity: Severity::from_score(total),
    }
}

/// Context modifiers for a lineage.
#[derive(Default, Clone, Copy)]
pub struct Context {
    pub network_rooted: bool,
    pub in_container: bool,
}

impl Context {
    fn multiplier(&self) -> (f64, Option<String>) {
        let mut m = 1.0;
        let mut notes = Vec::new();
        if self.network_rooted {
            m *= 1.3;
            notes.push("lineage rooted at a network daemon");
        }
        if self.in_container {
            m *= 1.1;
            notes.push("inside a container");
        }
        let note = if notes.is_empty() {
            None
        } else {
            Some(notes.join("; "))
        };
        (m, note)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::ProcKey;

    fn sig(id: &'static str, score: u32) -> Signal {
        Signal::new(
            id,
            score,
            &["T1543"],
            ProcKey {
                pid: 1,
                start_boottime: 1,
            },
            0,
            "",
        )
    }
    const PLAIN: Context = Context {
        network_rooted: false,
        in_container: false,
    };

    /// Measured, not predicted. A package upgrade that rewrites `/etc/pam.d`
    /// and `/etc/profile.d` emits two ids from one behaviour, and the
    /// distinct-id chain bonus scored that 82 -- a HIGH incident for
    /// `apt upgrade`. The scenario that found it is
    /// tests/noise/package_upgrade_login_files.sh.
    #[test]
    fn two_writes_of_the_same_family_do_not_chain_into_an_alert() {
        let s = score(
            &[sig("cred_config_write", 35), sig("persistence_write", 30)],
            PLAIN,
        );
        // Old behaviour: base 65, distinct 2, bonus 17 -> 82 (HIGH).
        assert_eq!(s.base, 35, "one behaviour contributes once");
        assert_eq!(s.chain_bonus, 0, "same family is not diverse evidence");
        assert!(
            s.total < 50,
            "a package upgrade must not alert: scored {}",
            s.total
        );
    }

    /// The other half of the same rule: grouping must not cost a real chain.
    /// A write, an escalation and a fileless exec are three behaviours, and
    /// three behaviours in one lineage is what the bonus exists to reward.
    #[test]
    fn diverse_evidence_still_chains() {
        let s = score(
            &[
                sig("cred_config_write", 35),
                sig("privilege_escalation", 40),
                sig("fileless_exec", 50),
            ],
            PLAIN,
        );
        assert_eq!(s.base, 125);
        assert_eq!(s.chain_bonus, 50, "(3 - 1) * 50 / 2");
        assert_eq!(s.severity, Severity::Critical);
    }

    fn at(id: &'static str, score: u32, ts_ns: u64) -> Signal {
        Signal::new(
            id,
            score,
            &["T1543"],
            ProcKey {
                pid: 1,
                start_boottime: 1,
            },
            ts_ns,
            "",
        )
    }

    /// A chain bonus claims these things happened as one operation. Shared
    /// lineage does not establish that: a `sudo` at the start of an admin
    /// session stays in the ancestry of everything that session later does.
    ///
    /// Measured in a 1.4-hour capture containing one `apt upgrade`: 93 critical
    /// incidents paired an escalation with a credential read, and the median
    /// gap between the two signals was 4,494 seconds.
    #[test]
    fn signals_an_hour_apart_are_not_one_operation() {
        let minute = 60 * 1_000_000_000u64;

        // Together: an escalation and a credential read seconds apart.
        let together = score(
            &[
                at("privilege_escalation", 40, 0),
                at("credential_store_read", 30, 2 * 1_000_000_000),
            ],
            PLAIN,
        );
        assert_eq!(together.severity, Severity::Critical);

        // The same two signals, 75 minutes apart -- the measured median. Only
        // the recent one counts, so this cannot alert on its own.
        let apart = score(
            &[
                at("privilege_escalation", 40, 0),
                at("credential_store_read", 30, 75 * minute),
            ],
            PLAIN,
        );
        assert_eq!(apart.base, 30, "only the recent signal is scored");
        assert_eq!(apart.chain_bonus, 0);
        assert!(apart.total < 50, "scored {}", apart.total);

        // The boundary is ten minutes, and it is inclusive on the near side.
        let inside = score(
            &[
                at("privilege_escalation", 40, 0),
                at("credential_store_read", 30, 9 * minute),
            ],
            PLAIN,
        );
        assert!(
            inside.chain_bonus > 0,
            "nine minutes is still one operation"
        );
    }

    /// The pre-existing rule, kept: the same id twice is one reason to worry.
    #[test]
    fn the_same_signal_twice_counts_once() {
        let s = score(
            &[
                sig("privilege_escalation", 40),
                sig("privilege_escalation", 40),
            ],
            PLAIN,
        );
        assert_eq!(s.base, 40);
        assert_eq!(s.chain_bonus, 0);
    }

    /// An id nobody grouped is its own family, so a new detection counts on its
    /// own rather than being silently folded into an existing behaviour.
    #[test]
    fn an_unknown_id_is_its_own_family() {
        assert_eq!(family("something_new"), "something_new");
        let s = score(
            &[sig("something_new", 40), sig("cred_config_write", 35)],
            PLAIN,
        );
        assert_eq!(s.base, 75);
        assert!(s.chain_bonus > 0);
    }
}
