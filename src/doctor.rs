//! Preflight checks. Attach failures are the number one support burden for
//! eBPF tools, so make the environment legible before anything else runs.

use std::fmt;
use std::fs;
use std::path::Path;

pub enum Status {
    Ok(String),
    Warn(String),
    Fail(String),
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Status::Ok(m) => write!(f, "  \x1b[32m[ ok ]\x1b[0m {m}"),
            Status::Warn(m) => write!(f, "  \x1b[33m[warn]\x1b[0m {m}"),
            Status::Fail(m) => write!(f, "  \x1b[31m[fail]\x1b[0m {m}"),
        }
    }
}

pub struct Report {
    pub checks: Vec<(&'static str, Status)>,
}

impl Report {
    pub fn fatal(&self) -> bool {
        self.checks
            .iter()
            .any(|(_, s)| matches!(s, Status::Fail(_)))
    }

    pub fn print(&self) {
        println!("kernelsentinel doctor\n");
        for (name, status) in &self.checks {
            println!("{name:<22} {status}");
        }
        println!();
    }
}

pub fn run() -> Report {
    let checks = vec![
        ("kernel", kernel_check()),
        ("btf", btf_check()),
        ("privileges", priv_check()),
        ("bpf lsm", lsm_check()),
        ("memlock", memlock_check()),
        ("trusted binaries", trusted_check()),
    ];

    Report { checks }
}

/// Which of the host's authentication programs and network daemons could be
/// resolved to a file identity.
///
/// Worth showing before anything runs, because the consequence is asymmetric. An
/// unresolved *credential reader* means its reads are no longer suppressed and
/// will alert -- noisy, but visible. The count going to zero would mean every
/// authentication on the host starts producing signals, and finding that out
/// from the alert stream is the slow way.
fn trusted_check() -> Status {
    let t = crate::fileid::TrustedBinaries::resolve_host();
    let msg = t.summary();
    if t.is_empty() {
        Status::Warn(format!(
            "{msg} -- nothing recognised, so every authentication read will alert"
        ))
    } else {
        Status::Ok(msg)
    }
}

fn kernel_check() -> Status {
    let release = uname_release();
    match parse_version(&release) {
        // 5.11, not 5.8. The ring buffer arrived in 5.8, but every program
        // calls fill_hdr, which uses bpf_get_current_task_btf() -- added in
        // 5.11. Reporting ok on 5.8 promised a load that would fail, which is
        // a worse answer than a clear refusal.
        Some((maj, min)) if (maj, min) >= (5, 11) => {
            Status::Ok(format!("{release} (5.11+, all BPF features present)"))
        }
        Some(_) => Status::Fail(format!(
            "{release} — kernel 5.11+ required (bpf_get_current_task_btf, used by every program)"
        )),
        None => Status::Warn(format!("{release} — could not parse version")),
    }
}

fn btf_check() -> Status {
    if Path::new("/sys/kernel/btf/vmlinux").exists() {
        Status::Ok("/sys/kernel/btf/vmlinux present (CO-RE enabled)".into())
    } else {
        Status::Fail("no kernel BTF — rebuild with CONFIG_DEBUG_INFO_BTF=y".into())
    }
}

fn priv_check() -> Status {
    // SAFETY: geteuid is always safe to call.
    if unsafe { libc::geteuid() } == 0 {
        Status::Ok("running as root".into())
    } else {
        Status::Fail("not root — need CAP_BPF+CAP_PERFMON (or run with sudo)".into())
    }
}

/// Is the bpf LSM in the kernel's active list?
///
/// `None` when the file cannot be read (securityfs not mounted), which is
/// genuinely unknown rather than false -- a caller must not treat it as proof
/// either way.
///
/// This decides whether the six `lsm/` sensors do anything, and it is the only
/// way to know: attaching them succeeds regardless. Measured on an Ubuntu
/// runner with `bpf` absent from this list -- all eleven programs attached, and
/// a real `chmod u+s` and a real read of `/etc/shadow` both produced nothing.
pub fn bpf_lsm_active() -> Option<bool> {
    fs::read_to_string("/sys/kernel/security/lsm")
        .ok()
        .map(|list| list.trim().split(',').any(|l| l == "bpf"))
}

fn lsm_check() -> Status {
    match fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(list) => {
            let list = list.trim();
            if list.split(',').any(|l| l == "bpf") {
                Status::Ok(format!("bpf LSM active ({list})"))
            } else {
                // There is no kprobe fallback. This used to say there was, which
                // is worse than saying nothing: an operator reading it concludes
                // the file, ptrace and socket detections still work, and they do
                // not. Worse still, the six lsm/ programs *attach* anyway --
                // the kernel accepts them whether or not bpf is in the active
                // LSM list -- so the agent's own "11 of 11 sensors attached" is
                // not evidence to the contrary. Run scripts/compat-probe.sh,
                // which provokes each sensor and reports which ones answered.
                Status::Warn(format!(
                    "bpf LSM not active ({list}) — the six lsm/ sensors still attach, but their \
                     hooks are only invoked when `bpf` is in this list, so file, \
                     credential-theft, fileless-exec and socket detections are very likely \
                     inert. `scripts/compat-probe.sh` provokes each sensor and reports which \
                     ones answered; add `bpf` to the lsm= kernel command line to enable them."
                ))
            }
        }
        Err(_) => Status::Warn("securityfs not mounted — cannot determine LSM list".into()),
    }
}

fn memlock_check() -> Status {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: lim is a valid rlimit for the duration of the call.
    unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut lim) };
    if lim.rlim_cur == libc::RLIM_INFINITY {
        Status::Ok("RLIMIT_MEMLOCK unlimited".into())
    } else {
        Status::Ok(format!(
            "RLIMIT_MEMLOCK {} KiB (kernel 5.11+ uses memcg accounting)",
            lim.rlim_cur / 1024
        ))
    }
}

fn uname_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn parse_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(['.', '-']);
    let maj = parts.next()?.parse().ok()?;
    let min = parts.next()?.parse().ok()?;
    Some((maj, min))
}
