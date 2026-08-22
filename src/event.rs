//! Rust mirror of `bpf/events.h`. Layout must match exactly; `Event::SIZE` is
//! checked against the C `sizeof` in tests/struct_layout.rs.

use std::ffi::CStr;

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_FILENAME: usize = 256;
pub const MAX_ARGV: usize = 512;

pub const EV_F_TRUNCATED: u16 = 1 << 0;
#[allow(dead_code)] // set by the path-resolving sensors in M2
pub const EV_F_DEGRADED_PATH: u16 = 1 << 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Exec,
    Exit,
    Fork,
    CredChange,
    Unknown(u16),
}

impl From<u16> for EventType {
    fn from(v: u16) -> Self {
        match v {
            1 => EventType::Exec,
            2 => EventType::Exit,
            3 => EventType::Fork,
            4 => EventType::CredChange,
            other => EventType::Unknown(other),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawEvent {
    pub ts_ns: u64,
    pub cgroup_id: u64,
    pub start_boottime: u64,
    pub cap_effective: u64,
    pub old_cap_effective: u64,
    pub child_start_boottime: u64,

    pub pid: u32,
    pub tgid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub old_uid: u32,
    pub old_gid: u32,
    pub old_euid: u32,
    pub old_egid: u32,
    pub exit_code: u32,
    pub argv_len: u32,
    pub child_pid: u32,

    pub r#type: u16,
    pub flags: u16,

    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; MAX_FILENAME],
    pub argv: [u8; MAX_ARGV],
}

impl RawEvent {
    pub const SIZE: usize = std::mem::size_of::<RawEvent>();

    /// Decode one ring buffer record.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::SIZE {
            return None;
        }
        // SAFETY: RawEvent is repr(C) and contains only integers and byte
        // arrays, so every bit pattern of the right length is a valid value.
        Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const RawEvent) })
    }

    pub fn event_type(&self) -> EventType {
        EventType::from(self.r#type)
    }

    pub fn comm(&self) -> String {
        cstr_lossy(&self.comm)
    }

    pub fn filename(&self) -> String {
        cstr_lossy(&self.filename)
    }

    /// argv arrives NUL-separated straight out of the process's `mm`.
    pub fn argv(&self) -> Vec<String> {
        let len = (self.argv_len as usize).min(MAX_ARGV);
        self.argv[..len]
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect()
    }

    pub fn truncated(&self) -> bool {
        self.flags & EV_F_TRUNCATED != 0
    }
}

fn cstr_lossy(buf: &[u8]) -> String {
    CStr::from_bytes_until_nul(buf)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_else(|_| String::from_utf8_lossy(buf).into_owned())
}

/// Linux capability bits worth naming in alerts. Not exhaustive -- these are
/// the ones that matter for privilege escalation.
pub fn cap_names(mask: u64) -> Vec<&'static str> {
    const CAPS: &[(u32, &str)] = &[
        (0, "CAP_CHOWN"),
        (1, "CAP_DAC_OVERRIDE"),
        (2, "CAP_DAC_READ_SEARCH"),
        (6, "CAP_SETGID"),
        (7, "CAP_SETUID"),
        (8, "CAP_SETPCAP"),
        (12, "CAP_NET_ADMIN"),
        (16, "CAP_SYS_MODULE"),
        (19, "CAP_SYS_PTRACE"),
        (21, "CAP_SYS_ADMIN"),
        (38, "CAP_BPF"),
    ];
    CAPS.iter()
        .filter(|(bit, _)| mask & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect()
}
