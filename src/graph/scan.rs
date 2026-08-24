//! Bootstrap the graph from /proc.
//!
//! eBPF only sees events from attach time onward. Without this, every process
//! that predates the daemon is invisible, and any chain rooted in one of them
//! is unattributable.

use std::fs;

use super::{Origin, ProcKey, ProcNode, ProcessGraph};

/// `/proc/<pid>/stat` reports start time in clock ticks since boot, while
/// `task->start_boottime` from BPF is exact nanoseconds. Converting gives a
/// value truncated to tick granularity, which is why ProcessGraph::resolve
/// reconciles the two within a tolerance rather than comparing for equality.
fn clock_ticks_hz() -> u64 {
    // SAFETY: sysconf with a valid name has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz > 0 { hz as u64 } else { 100 }
}

pub struct ScanResult {
    pub scanned: usize,
    pub failed: usize,
}

/// Populate `graph` with every process currently visible in /proc.
pub fn bootstrap(graph: &mut ProcessGraph) -> ScanResult {
    let hz = clock_ticks_hz();
    let ns_per_tick = 1_000_000_000u64 / hz;

    let mut edges: Vec<(ProcKey, u32)> = Vec::new();
    let mut scanned = 0usize;
    let mut failed = 0usize;

    let Ok(entries) = fs::read_dir("/proc") else {
        return ScanResult {
            scanned: 0,
            failed: 1,
        };
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };

        match scan_one(pid, ns_per_tick) {
            Some((node, ppid)) => {
                edges.push((node.key, ppid));
                graph.insert_scanned(node);
                scanned += 1;
            }
            // Processes exit while we walk /proc; that is expected, not an error.
            None => failed += 1,
        }
    }

    graph.link_scanned(&edges);
    ScanResult { scanned, failed }
}

fn scan_one(pid: u32, ns_per_tick: u64) -> Option<(ProcNode, u32)> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;

    // comm is in parentheses and may itself contain spaces or parens, so
    // split on the *last* ')' rather than tokenizing the whole line.
    let close = stat.rfind(')')?;
    let comm = stat.get(stat.find('(')? + 1..close)?.to_string();
    let rest: Vec<&str> = stat.get(close + 2..)?.split_whitespace().collect();

    // Fields after comm start at stat field 3, so field N is index N-3:
    // rest[0] is state, rest[1] is ppid (field 4), rest[19] is starttime (22).
    let ppid: u32 = rest.get(1)?.parse().ok()?;
    let starttime_ticks: u64 = rest.get(19)?.parse().ok()?;

    let key = ProcKey {
        pid,
        start_boottime: starttime_ticks * ns_per_tick,
    };

    let mut node = ProcNode::new(key, Origin::Scanned);
    node.comm = comm;
    node.argv = read_cmdline(pid);
    node.exe = fs::read_link(format!("/proc/{pid}/exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Some((uid, euid)) = read_ids(pid) {
        node.uid = uid;
        node.euid = euid;
    }

    Some((node, ppid))
}

fn read_cmdline(pid: u32) -> Vec<String> {
    fs::read(format!("/proc/{pid}/cmdline"))
        .map(|raw| {
            raw.split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Uid line is: real  effective  saved  fs
fn read_ids(pid: u32) -> Option<(u32, u32)> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("Uid:"))?;
    let mut vals = line.split_whitespace().skip(1);
    let uid = vals.next()?.parse().ok()?;
    let euid = vals.next()?.parse().ok()?;
    Some((uid, euid))
}
