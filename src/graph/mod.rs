//! The process graph. Everything the detection engine does is a query over
//! this structure.

pub mod scan;

use std::collections::HashMap;
use std::time::Duration;

use crate::decoded::Event;

/// Scanned start times come from `/proc/<pid>/stat`, which reports clock ticks
/// (10ms) rather than the exact nanoseconds BPF sees. A process observed both
/// ways therefore yields two different keys unless we reconcile them within
/// one tick.
const SCAN_START_TOLERANCE_NS: u64 = 20_000_000;

/// Process identity. A bare PID is not enough: PIDs recycle within seconds on
/// a busy host, and a recycled PID means attributing an attacker's action to
/// an innocent process.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct ProcKey {
    pub pid: u32,
    pub start_boottime: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    /// Seen live by a sensor; history is complete from that point.
    Observed,
    /// Reconstructed from /proc at startup; history before attach is unknown.
    Scanned,
}

#[derive(Clone, Copy, Debug)]
pub struct CredSnapshot {
    pub ts_ns: u64,
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    pub caps: u64,
}

#[derive(Clone, Debug)]
pub struct ProcNode {
    pub key: ProcKey,
    pub parent: Option<ProcKey>,
    pub children: Vec<ProcKey>,
    pub comm: String,
    pub exe: String,
    /// The canonical name of the trusted system binary this process is running,
    /// established by file identity at exec. Empty means "not a known system
    /// binary", including for every process whose exec was never observed.
    ///
    /// Deliberately not derived from `comm` or `exe`: both are strings the
    /// process can arrange to say anything. A detection that turns on this
    /// field is asking what the kernel mapped, not what the process calls
    /// itself.
    pub trusted: String,
    pub argv: Vec<String>,
    pub uid: u32,
    pub euid: u32,
    pub cgroup_id: u64,
    pub container: String,
    pub cred_history: Vec<CredSnapshot>,
    pub started: u64,
    pub exited: Option<u64>,
    pub origin: Origin,
}

impl ProcNode {
    fn new(key: ProcKey, origin: Origin) -> Self {
        Self {
            key,
            parent: None,
            children: Vec::new(),
            comm: String::new(),
            exe: String::new(),
            trusted: String::new(),
            argv: Vec::new(),
            uid: 0,
            euid: 0,
            cgroup_id: 0,
            container: String::new(),
            cred_history: Vec::new(),
            started: key.start_boottime,
            exited: None,
            origin,
        }
    }

    pub fn alive(&self) -> bool {
        self.exited.is_none()
    }

    /// Display name: the executable if we have one, else the kernel comm.
    pub fn name(&self) -> &str {
        if self.exe.is_empty() {
            &self.comm
        } else {
            &self.exe
        }
    }
}

pub struct GraphStats {
    pub nodes: usize,
    pub alive: usize,
    pub reaped: u64,
    pub evicted: u64,
    pub adopted: u64,
}

pub struct ProcessGraph {
    nodes: HashMap<ProcKey, ProcNode>,
    /// Most recent key seen for a PID, for reconciling scanned nodes.
    by_pid: HashMap<u32, ProcKey>,
    max_processes: usize,
    retain_ns: u64,
    reaped: u64,
    evicted: u64,
    adopted: u64,
    /// The host's own mount-namespace inode, when known.
    ///
    /// Carried here rather than read from /proc inside a detector, because a
    /// detector that consults the live system stops being deterministic under
    /// replay -- the same capture would decide differently on different
    /// machines. Zero means "unknown", and the detections that depend on it
    /// simply do not fire, which is the honest answer for a replayed capture
    /// that never recorded it.
    host_mnt_ns: u32,
}

impl ProcessGraph {
    /// Record the host's mount-namespace inode, from `/proc/1/ns/mnt`.
    pub fn set_host_mnt_ns(&mut self, inum: u32) {
        self.host_mnt_ns = inum;
    }

    /// The host's mount-namespace inode, or 0 when unknown.
    pub fn host_mnt_ns(&self) -> u32 {
        self.host_mnt_ns
    }

    /// `max_processes` and `retain` are not optional tuning knobs. An unbounded
    /// graph is how a monitoring agent becomes the thing that OOMs the host.
    pub fn new(max_processes: usize, retain: Duration) -> Self {
        Self {
            nodes: HashMap::new(),
            by_pid: HashMap::new(),
            max_processes,
            retain_ns: retain.as_nanos() as u64,
            reaped: 0,
            evicted: 0,
            adopted: 0,
            host_mnt_ns: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn get(&self, key: &ProcKey) -> Option<&ProcNode> {
        self.nodes.get(key)
    }

    pub fn nodes(&self) -> impl Iterator<Item = &ProcNode> {
        self.nodes.values()
    }

    pub fn stats(&self) -> GraphStats {
        GraphStats {
            nodes: self.nodes.len(),
            alive: self.nodes.values().filter(|n| n.alive()).count(),
            reaped: self.reaped,
            evicted: self.evicted,
            adopted: self.adopted,
        }
    }

    /// Walk from a node up to the root, oldest ancestor last.
    pub fn ancestry(&self, key: &ProcKey) -> Vec<&ProcNode> {
        let mut chain = Vec::new();
        let mut cur = Some(*key);
        // Bounded: a corrupted parent link must not spin forever.
        for _ in 0..64 {
            let Some(k) = cur else { break };
            let Some(node) = self.nodes.get(&k) else {
                break;
            };
            chain.push(node);
            cur = node.parent;
        }
        chain
    }

    /// Resolve a (pid, start_boottime) pair to a key, reconciling a scanned
    /// node whose start time is tick-truncated rather than exact.
    fn resolve(&mut self, pid: u32, start: u64) -> ProcKey {
        let exact = ProcKey {
            pid,
            start_boottime: start,
        };
        if self.nodes.contains_key(&exact) {
            return exact;
        }
        if let Some(&existing) = self.by_pid.get(&pid) {
            if existing == exact {
                return exact;
            }
            if let Some(node) = self.nodes.get(&existing) {
                if node.alive()
                    && node.origin == Origin::Scanned
                    && start.abs_diff(existing.start_boottime) <= SCAN_START_TOLERANCE_NS
                {
                    self.rekey(existing, exact);
                    self.adopted += 1;
                    return exact;
                }
            }
        }
        exact
    }

    /// Move a node to a new key, repairing both directions of every edge.
    fn rekey(&mut self, from: ProcKey, to: ProcKey) {
        let Some(mut node) = self.nodes.remove(&from) else {
            return;
        };
        node.key = to;
        node.origin = Origin::Observed;

        if let Some(parent) = node.parent {
            if let Some(pn) = self.nodes.get_mut(&parent) {
                for child in pn.children.iter_mut() {
                    if *child == from {
                        *child = to;
                    }
                }
            }
        }
        for child in node.children.clone() {
            if let Some(cn) = self.nodes.get_mut(&child) {
                cn.parent = Some(to);
            }
        }
        self.by_pid.insert(to.pid, to);
        self.nodes.insert(to, node);
    }

    fn ensure(&mut self, key: ProcKey, origin: Origin) -> &mut ProcNode {
        self.by_pid.insert(key.pid, key);
        self.nodes
            .entry(key)
            .or_insert_with(|| ProcNode::new(key, origin))
    }

    /// Insert a node built by the /proc scanner.
    pub fn insert_scanned(&mut self, node: ProcNode) {
        self.by_pid.insert(node.key.pid, node.key);
        self.nodes.insert(node.key, node);
    }

    /// Link parent/child edges after a bulk scan, once every node exists.
    pub fn link_scanned(&mut self, edges: &[(ProcKey, u32)]) {
        for (child, ppid) in edges {
            let Some(&parent) = self.by_pid.get(ppid) else {
                continue;
            };
            if parent == *child {
                continue;
            }
            if let Some(cn) = self.nodes.get_mut(child) {
                cn.parent = Some(parent);
            }
            if let Some(pn) = self.nodes.get_mut(&parent) {
                pn.children.push(*child);
            }
        }
    }

    pub fn apply(&mut self, ev: &Event) {
        use crate::event::EventType;
        match ev.event_type() {
            EventType::Fork => self.on_fork(ev),
            EventType::Exec => self.on_exec(ev),
            EventType::Exit => self.on_exit(ev),
            EventType::CredChange => self.on_cred(ev),
            // File opens describe behavior, not process structure; the
            // detection engine consumes them, the graph does not.
            EventType::FileOpen
            | EventType::FileMode
            | EventType::Setcap
            | EventType::Ptrace
            | EventType::ExecAnon
            | EventType::Module
            | EventType::SockConnect => {}
            EventType::Unknown(_) => {}
        }
    }

    fn on_fork(&mut self, ev: &Event) {
        let parent = self.resolve(ev.tgid, ev.start_boottime);
        {
            let pn = self.ensure(parent, Origin::Observed);
            if pn.comm.is_empty() {
                pn.comm = ev.comm.clone();
            }
        }
        let child = ProcKey {
            pid: ev.child_pid,
            start_boottime: ev.child_start_boottime,
        };
        {
            let cn = self.ensure(child, Origin::Observed);
            cn.parent = Some(parent);
            cn.started = ev.ts_ns;
            cn.uid = ev.uid;
            cn.euid = ev.euid;
            cn.cgroup_id = ev.cgroup_id;
            if !ev.container.is_empty() {
                cn.container = ev.container.clone();
            }
            // Inherited until the child execs; showing the parent's name is
            // more useful than showing nothing.
            if cn.comm.is_empty() {
                cn.comm = ev.comm.clone();
            }
        }
        if let Some(pn) = self.nodes.get_mut(&parent) {
            if !pn.children.contains(&child) {
                pn.children.push(child);
            }
        }
    }

    fn on_exec(&mut self, ev: &Event) {
        let key = self.resolve(ev.tgid, ev.start_boottime);
        let (comm, exe, argv) = (ev.comm.clone(), ev.filename.clone(), ev.argv.clone());
        let trusted = ev.exe_trusted.clone();
        let node = self.ensure(key, Origin::Observed);
        node.comm = comm;
        node.exe = exe;
        node.argv = argv;
        node.trusted = trusted;
        node.uid = ev.uid;
        node.euid = ev.euid;
        node.cgroup_id = ev.cgroup_id;
        if !ev.container.is_empty() {
            node.container = ev.container.clone();
        }
    }

    fn on_exit(&mut self, ev: &Event) {
        let key = self.resolve(ev.tgid, ev.start_boottime);
        let ts = ev.ts_ns;
        if let Some(node) = self.nodes.get_mut(&key) {
            node.exited = Some(ts);
        }
        // An exit event for a process we never saw start is not worth a node.
        self.by_pid.remove(&key.pid);
    }

    fn on_cred(&mut self, ev: &Event) {
        let key = self.resolve(ev.tgid, ev.start_boottime);
        let snap = CredSnapshot {
            ts_ns: ev.ts_ns,
            uid: ev.uid,
            euid: ev.euid,
            gid: ev.gid,
            egid: ev.egid,
            caps: ev.cap_effective,
        };
        let node = self.ensure(key, Origin::Observed);
        if node.comm.is_empty() {
            node.comm = ev.comm.clone();
        }
        node.uid = ev.uid;
        node.euid = ev.euid;
        if !ev.container.is_empty() {
            node.container = ev.container.clone();
        }
        // Bounded: a process flapping credentials must not grow without limit.
        if node.cred_history.len() < 64 {
            node.cred_history.push(snap);
        }
    }

    /// Drop exited nodes past the retention window, then evict under pressure.
    pub fn reap(&mut self, now_ns: u64) {
        let retain = self.retain_ns;
        let expired: Vec<ProcKey> = self
            .nodes
            .values()
            .filter(|n| n.exited.is_some_and(|e| now_ns.saturating_sub(e) > retain))
            .map(|n| n.key)
            .collect();
        for key in expired {
            self.remove(key);
            self.reaped += 1;
        }

        while self.nodes.len() > self.max_processes {
            // Prefer the longest-dead node; fall back to the oldest live one
            // only if everything in the graph is still running.
            let victim = self
                .nodes
                .values()
                .filter(|n| !n.alive())
                .min_by_key(|n| n.exited.unwrap_or(u64::MAX))
                .or_else(|| self.nodes.values().min_by_key(|n| n.started))
                .map(|n| n.key);
            let Some(victim) = victim else { break };
            self.remove(victim);
            self.evicted += 1;
        }
    }

    fn remove(&mut self, key: ProcKey) {
        let Some(node) = self.nodes.remove(&key) else {
            return;
        };
        if let Some(parent) = node.parent {
            if let Some(pn) = self.nodes.get_mut(&parent) {
                pn.children.retain(|c| *c != key);
            }
        }
        // Orphaned children keep their own nodes; the chain simply ends here.
        for child in node.children {
            if let Some(cn) = self.nodes.get_mut(&child) {
                cn.parent = None;
            }
        }
        if self.by_pid.get(&key.pid) == Some(&key) {
            self.by_pid.remove(&key.pid);
        }
    }

    /// Roots for display: nodes with no parent in the graph.
    pub fn roots(&self) -> Vec<ProcKey> {
        let mut roots: Vec<ProcKey> = self
            .nodes
            .values()
            .filter(|n| n.parent.is_none_or(|p| !self.nodes.contains_key(&p)))
            .map(|n| n.key)
            .collect();
        roots.sort();
        roots
    }

    pub fn children_of(&self, key: &ProcKey) -> Vec<ProcKey> {
        let mut kids = self
            .nodes
            .get(key)
            .map(|n| n.children.clone())
            .unwrap_or_default();
        kids.retain(|k| self.nodes.contains_key(k));
        kids.sort();
        kids
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoded::Event;

    fn blank() -> Event {
        serde_json::from_str(r#"{"ts_ns":0,"type":0,"tgid":0,"ppid":0,"start_boottime":0}"#)
            .unwrap()
    }

    fn fork_ev(parent: u32, pstart: u64, child: u32, cstart: u64, ts: u64) -> Event {
        let mut e = blank();
        e.r#type = 3;
        e.tgid = parent;
        e.start_boottime = pstart;
        e.child_pid = child;
        e.child_start_boottime = cstart;
        e.ts_ns = ts;
        e
    }

    fn exit_ev(pid: u32, start: u64, ts: u64) -> Event {
        let mut e = blank();
        e.r#type = 2;
        e.tgid = pid;
        e.start_boottime = start;
        e.ts_ns = ts;
        e
    }

    fn graph() -> ProcessGraph {
        ProcessGraph::new(1000, Duration::from_secs(300))
    }

    #[test]
    fn fork_builds_parent_child_edges() {
        let mut g = graph();
        g.apply(&fork_ev(100, 1, 200, 2, 10));
        let parent = ProcKey {
            pid: 100,
            start_boottime: 1,
        };
        let child = ProcKey {
            pid: 200,
            start_boottime: 2,
        };
        assert_eq!(g.get(&child).unwrap().parent, Some(parent));
        assert_eq!(g.children_of(&parent), vec![child]);
    }

    #[test]
    fn pid_reuse_creates_distinct_nodes() {
        let mut g = graph();
        g.apply(&fork_ev(1, 0, 200, 100, 10));
        g.apply(&exit_ev(200, 100, 20));
        // Same PID, different start time: a genuinely different process.
        g.apply(&fork_ev(1, 0, 200, 900, 30));
        assert_eq!(g.len(), 3, "reused PID must not collapse into one node");
        let old = ProcKey {
            pid: 200,
            start_boottime: 100,
        };
        let new = ProcKey {
            pid: 200,
            start_boottime: 900,
        };
        assert!(g.get(&old).unwrap().exited.is_some());
        assert!(g.get(&new).unwrap().alive());
    }

    #[test]
    fn scanned_node_is_adopted_by_exact_event() {
        let mut g = graph();
        // Scanner saw a tick-truncated start time.
        let mut node = ProcNode::new(
            ProcKey {
                pid: 500,
                start_boottime: 10_000_000,
            },
            Origin::Scanned,
        );
        node.comm = "victim".into();
        g.insert_scanned(node);

        // BPF reports the exact nanosecond value for the same process.
        g.apply(&exit_ev(500, 10_004_321, 50));

        assert_eq!(
            g.len(),
            1,
            "scanned and observed must reconcile to one node"
        );
        assert_eq!(g.stats().adopted, 1);
    }

    #[test]
    fn distant_start_time_is_not_adopted() {
        let mut g = graph();
        g.insert_scanned(ProcNode::new(
            ProcKey {
                pid: 500,
                start_boottime: 10_000_000,
            },
            Origin::Scanned,
        ));
        // A second past the scanned value is a different process, not drift.
        g.apply(&fork_ev(500, 1_010_000_000, 600, 5, 50));
        assert_eq!(g.len(), 3);
        assert_eq!(g.stats().adopted, 0);
    }

    #[test]
    fn retention_reaps_only_expired_exited_nodes() {
        let mut g = ProcessGraph::new(1000, Duration::from_secs(5));
        g.apply(&fork_ev(1, 0, 200, 2, 10));
        g.apply(&exit_ev(200, 2, 1_000_000_000));
        g.reap(3_000_000_000); // 2s later: inside the window
        assert_eq!(g.len(), 2);
        g.reap(9_000_000_000); // 8s later: expired
        assert_eq!(g.stats().reaped, 1);
        assert!(
            g.get(&ProcKey {
                pid: 200,
                start_boottime: 2
            })
            .is_none()
        );
    }

    #[test]
    fn cap_is_enforced_under_pressure() {
        let mut g = ProcessGraph::new(10, Duration::from_secs(3600));
        for i in 0..50u32 {
            g.apply(&fork_ev(1, 0, 1000 + i, i as u64 + 1, i as u64));
            g.apply(&exit_ev(1000 + i, i as u64 + 1, i as u64 + 1));
        }
        g.reap(100);
        assert!(g.len() <= 10, "graph exceeded its cap: {}", g.len());
        assert!(g.stats().evicted > 0);
    }

    #[test]
    fn ancestry_terminates_on_cycle() {
        let mut g = graph();
        g.apply(&fork_ev(1, 0, 2, 1, 10));
        // Force a cycle that could only arise from corruption.
        let a = ProcKey {
            pid: 1,
            start_boottime: 0,
        };
        let b = ProcKey {
            pid: 2,
            start_boottime: 1,
        };
        g.nodes.get_mut(&a).unwrap().parent = Some(b);
        assert!(g.ancestry(&b).len() <= 64);
    }

    #[test]
    fn removing_a_node_orphans_children_without_dangling() {
        let mut g = graph();
        g.apply(&fork_ev(1, 0, 2, 1, 10));
        g.apply(&fork_ev(2, 1, 3, 2, 20));
        let mid = ProcKey {
            pid: 2,
            start_boottime: 1,
        };
        g.remove(mid);
        let leaf = ProcKey {
            pid: 3,
            start_boottime: 2,
        };
        assert_eq!(g.get(&leaf).unwrap().parent, None);
        assert!(g.roots().contains(&leaf));
    }
}
