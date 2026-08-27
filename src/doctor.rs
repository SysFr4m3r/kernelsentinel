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
    ];

    Report { checks }
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

fn lsm_check() -> Status {
    match fs::read_to_string("/sys/kernel/security/lsm") {
        Ok(list) => {
            let list = list.trim();
            if list.split(',').any(|l| l == "bpf") {
                Status::Ok(format!("bpf LSM active ({list})"))
            } else {
                Status::Warn(format!(
                    "bpf LSM not active ({list}) — LSM sensors will fall back to kprobes"
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
