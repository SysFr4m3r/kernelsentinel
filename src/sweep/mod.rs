//! A point-in-time inventory of what is on this host, rather than a stream of
//! what happens to it.
//!
//! The rest of this tool is event-driven, and that leaves a hole the size of
//! the usual intrusion: an attacker who arrived before the agent did is
//! invisible to it. Their key is already in `authorized_keys`, their unit file
//! is already in `/etc/systemd/system`, their SUID binary already exists.
//! Nothing *happens*, so nothing fires.
//!
//! Sweep asks the complementary question. To survive a reboot or your logging
//! out, an intruder has to leave something somewhere, and those artifacts are
//! enumerable now -- whenever they were created. Where possible each check
//! compares against an authority the host already keeps rather than against a
//! list this project maintains: the package manager's manifests, systemd's own
//! symlink conventions, pam-auth-update's state directory.
//!
//! What it cannot do, stated here because a sweep that overclaims is worse than
//! none: it reads the kernel it is auditing. A rootkit hiding a module from
//! /proc/modules hides it here too. A clean result means the artifacts it knows
//! about are absent, which is not the same as a clean host.

pub mod checks;
pub mod packages;

use std::fmt;

/// One thing worth an operator's attention, or the absence of any.
pub enum Finding {
    /// Nothing unexpected. Carries what was examined, because "0 findings" and
    /// "0 files examined" look identical in a report and mean opposite things.
    Clear(String),
    /// Present and worth a look, but routinely explainable.
    Notice(String, Vec<String>),
    /// Hard to explain innocently.
    Suspect(String, Vec<String>),
    /// The check could not run. Never silently counted as clear.
    Unknown(String),
}

impl Finding {
    fn tag(&self) -> &'static str {
        match self {
            Finding::Clear(_) => "\x1b[32m[ ok ]\x1b[0m",
            Finding::Notice(..) => "\x1b[33m[note]\x1b[0m",
            Finding::Suspect(..) => "\x1b[31m[ !! ]\x1b[0m",
            Finding::Unknown(_) => "\x1b[33m[ ?? ]\x1b[0m",
        }
    }
    fn summary(&self) -> &str {
        match self {
            Finding::Clear(s) | Finding::Unknown(s) => s,
            Finding::Notice(s, _) | Finding::Suspect(s, _) => s,
        }
    }
    fn items(&self) -> &[String] {
        match self {
            Finding::Notice(_, i) | Finding::Suspect(_, i) => i,
            _ => &[],
        }
    }
    pub fn is_suspect(&self) -> bool {
        matches!(self, Finding::Suspect(..))
    }
}

pub struct Sweep {
    pub checks: Vec<(&'static str, Finding)>,
    pub manifest_source: &'static str,
    pub manifest_paths: usize,
}

impl fmt::Display for Sweep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "kernelsentinel sweep\n")?;
        for (name, finding) in &self.checks {
            writeln!(f, "{:<22} {} {}", name, finding.tag(), finding.summary())?;
            for item in finding.items() {
                writeln!(f, "                            {item}")?;
            }
        }
        writeln!(
            f,
            "\ncompared against {} ({} paths)",
            self.manifest_source, self.manifest_paths
        )?;
        // The limits belong in the output, not only in the documentation. An
        // operator reads this at the moment they are deciding whether to trust
        // the host, which is exactly when an overclaim does its damage.
        writeln!(
            f,
            "\nThis reads the kernel it is auditing: a rootkit that hides a module or a\n\
             process from /proc hides it here too. Nothing found means the artifacts\n\
             this knows about are absent, not that the host is clean."
        )
    }
}

impl Sweep {
    /// Whether anything needs a human. Used for the exit code, so a sweep can
    /// sit in cron and stay quiet until it has something to say.
    pub fn needs_attention(&self) -> bool {
        self.checks.iter().any(|(_, f)| f.is_suspect())
    }
}

pub fn run() -> Sweep {
    let manifest = packages::Manifest::load();
    let checks = vec![
        ("setuid binaries", checks::suid(&manifest)),
        ("persistence", checks::persistence(&manifest)),
        ("running processes", checks::deleted_executables()),
        ("kernel modules", checks::modules()),
        ("escape hatches", checks::escape_hatches()),
        ("ssh authorized keys", checks::authorized_keys()),
    ];
    Sweep {
        checks,
        manifest_source: manifest.source(),
        manifest_paths: manifest.len(),
    }
}
