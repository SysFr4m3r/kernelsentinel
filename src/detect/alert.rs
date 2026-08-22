//! Human-readable incident rendering. One block per incident, showing the
//! chain of signals in causal order and the score broken down into named parts,
//! because an unexplained number is one nobody acts on.

use crate::clock::BootClock;
use crate::graph::ProcessGraph;

use super::{Incident, Severity};

fn color(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "\x1b[1;31m", // bold red
        Severity::High => "\x1b[31m",
        Severity::Medium => "\x1b[33m",
        Severity::Low => "\x1b[36m",
        Severity::Info => "\x1b[2m",
    }
}

/// Render one incident to a string. `graph` supplies the lineage names.
pub fn render(inc: &Incident, graph: &ProcessGraph, clock: &BootClock) -> String {
    let sev = inc.score.severity;
    let mut out = String::new();
    let reset = "\x1b[0m";

    out.push_str(&format!(
        "\n{}{}{}  risk {}/100  ",
        color(sev),
        sev.label(),
        reset,
        inc.score.total
    ));
    out.push_str(&format!("[{}]\n", inc.attack.join(", ")));

    // Lineage as names, root first.
    let chain: Vec<String> = graph
        .ancestry(&inc.subject)
        .iter()
        .rev()
        .map(|n| format!("{}({})", n.comm, n.key.pid))
        .collect();
    if !chain.is_empty() {
        out.push_str(&format!("  {}\n", chain.join(" -> ")));
    }

    // Signals in causal order.
    for s in &inc.signals {
        out.push_str(&format!(
            "    {} {:<22} {}  (+{})\n",
            clock.format(s.ts_ns),
            s.id,
            s.detail,
            s.score
        ));
    }

    // Score breakdown.
    out.push_str(&format!(
        "  score: base {} + chain {} ",
        inc.score.base, inc.score.chain_bonus
    ));
    if (inc.score.context_mult - 1.0).abs() > f64::EPSILON {
        out.push_str(&format!("x{:.2} ", inc.score.context_mult));
        if let Some(note) = &inc.score.context_note {
            out.push_str(&format!("({note}) "));
        }
    }
    out.push_str(&format!("= {}\n", inc.score.total));
    out
}
