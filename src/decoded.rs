//! The decoded event. `RawEvent` is the wire format read straight out of the
//! ring buffer; `Event` is what the graph and detection engine consume. Keeping
//! them separate means the logic never depends on the BPF struct layout, and it
//! makes record/replay possible: a captured `Event` is JSON, and replaying it
//! drives exactly the same code path as a live one.

use serde::{Deserialize, Serialize};

use crate::event::{EventType, RawEvent};

/// Numeric fields default to 0 and are omitted from JSON when unset, so a
/// captured event only carries the fields its type actually uses.
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
fn is_false(v: &bool) -> bool {
    !*v
}
fn is_empty_str(v: &str) -> bool {
    v.is_empty()
}
fn is_empty_vec(v: &[String]) -> bool {
    v.is_empty()
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Event {
    pub ts_ns: u64,
    /// Raw discriminant; use `event_type()` for the enum.
    pub r#type: u16,
    pub tgid: u32,
    pub ppid: u32,
    pub start_boottime: u64,

    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub uid: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub gid: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub euid: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub egid: u32,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub cgroup_id: u64,

    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub comm: String,
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub filename: String,
    #[serde(default, skip_serializing_if = "is_empty_vec")]
    pub argv: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,

    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub exit_code: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub child_pid: u32,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub child_start_boottime: u64,

    // credential change
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub old_uid: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub old_gid: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub old_euid: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub old_egid: u32,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub cap_effective: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub old_cap_effective: u64,

    // file events
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub file_mode: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub old_file_mode: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub watch_id: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub degraded_path: bool,

    // ptrace / anon-exec / module
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub target_pid: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub aux: u32,

    /// Container label (runtime:id), resolved in userspace from cgroup_id at
    /// capture time so it persists into a replayed capture.
    #[serde(default, skip_serializing_if = "is_empty_str")]
    pub container: String,
}

impl Event {
    pub fn event_type(&self) -> EventType {
        EventType::from(self.r#type)
    }

    pub fn opened_for_write(&self) -> bool {
        self.file_mode & 0x2 != 0
    }

    pub fn ptrace_is_attach(&self) -> bool {
        self.aux & 0x02 != 0 // PTRACE_MODE_ATTACH
    }

    pub fn exec_source(&self) -> &'static str {
        match self.aux {
            1 => "memfd",
            2 => "anon-inode",
            3 => "deleted-file",
            _ => "unknown",
        }
    }

    pub fn module_origin(&self) -> &'static str {
        match self.aux {
            1 => "init_module",
            2 => "finit_module",
            _ => "",
        }
    }

    /// Which setuid/setgid bit was newly gained (EV_FILE_MODE).
    pub fn gained_bits(&self) -> &'static str {
        const S_ISUID: u32 = 0o4000;
        const S_ISGID: u32 = 0o2000;
        let suid = self.file_mode & S_ISUID != 0 && self.old_file_mode & S_ISUID == 0;
        let sgid = self.file_mode & S_ISGID != 0 && self.old_file_mode & S_ISGID == 0;
        match (suid, sgid) {
            (true, true) => "SUID+SGID",
            (true, false) => "SUID",
            (false, true) => "SGID",
            (false, false) => "none",
        }
    }
}

impl From<&RawEvent> for Event {
    fn from(r: &RawEvent) -> Self {
        Event {
            ts_ns: r.ts_ns,
            r#type: r.r#type,
            tgid: r.tgid,
            ppid: r.ppid,
            start_boottime: r.start_boottime,
            uid: r.uid,
            gid: r.gid,
            euid: r.euid,
            egid: r.egid,
            cgroup_id: r.cgroup_id,
            comm: r.comm(),
            filename: r.filename(),
            argv: r.argv(),
            truncated: r.truncated(),
            exit_code: r.exit_code,
            child_pid: r.child_pid,
            child_start_boottime: r.child_start_boottime,
            old_uid: r.old_uid,
            old_gid: r.old_gid,
            old_euid: r.old_euid,
            old_egid: r.old_egid,
            cap_effective: r.cap_effective,
            old_cap_effective: r.old_cap_effective,
            file_mode: r.file_mode,
            old_file_mode: r.old_file_mode,
            watch_id: r.watch_id,
            degraded_path: r.degraded_path(),
            target_pid: r.target_pid,
            aux: r.aux,
            container: crate::container::parse_container(&r.cgroup_name())
                .map(|c| c.label())
                .unwrap_or_default(),
        }
    }
}
