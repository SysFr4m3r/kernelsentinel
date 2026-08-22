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

    let base: u32 = signals.iter().map(|s| s.score).sum();

    // Count *distinct* detection kinds; three ptrace signals are not three
    // independent reasons to worry.
    let mut kinds: Vec<&str> = signals.iter().map(|s| s.id).collect();
    kinds.sort_unstable();
    kinds.dedup();
    let distinct = kinds.len() as u32;

    let max = signals.iter().map(|s| s.score).max().unwrap_or(0);
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
