//! Rust mirror of `bpf/events.h`. Layout must match exactly; `Event::SIZE` is
//! checked against the C `sizeof` in tests/struct_layout.rs.

use std::ffi::CStr;

pub const TASK_COMM_LEN: usize = 16;
pub const MAX_FILENAME: usize = 256;
pub const MAX_ARGV: usize = 512;
pub const MAX_CGROUP_NAME: usize = 64;

pub const EV_F_TRUNCATED: u16 = 1 << 0;
#[allow(dead_code)] // set by the path-resolving sensors in M2
pub const EV_F_DEGRADED_PATH: u16 = 1 << 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    Exec,
    Exit,
    Fork,
    CredChange,
    FileOpen,
    FileMode,
    Setcap,
    Ptrace,
    ExecAnon,
    Module,
    SockConnect,
    Unknown(u16),
}

impl From<u16> for EventType {
    fn from(v: u16) -> Self {
        match v {
            1 => EventType::Exec,
            2 => EventType::Exit,
            3 => EventType::Fork,
            4 => EventType::CredChange,
            5 => EventType::FileOpen,
            6 => EventType::FileMode,
            7 => EventType::Setcap,
            8 => EventType::Ptrace,
            9 => EventType::ExecAnon,
            10 => EventType::Module,
            11 => EventType::SockConnect,
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
    pub file_mode: u32,
    pub old_file_mode: u32,
    pub watch_id: u32,
    pub target_pid: u32,
    pub aux: u32,

    pub r#type: u16,
    pub flags: u16,

    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; MAX_FILENAME],
    pub argv: [u8; MAX_ARGV],
    pub cgroup_name: [u8; MAX_CGROUP_NAME],
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

    pub fn cgroup_name(&self) -> String {
        cstr_lossy(&self.cgroup_name)
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

    /// EV_PTRACE: was this an attach/write-capable access, not just a read?
    pub fn ptrace_is_attach(&self) -> bool {
        self.aux & 0x02 != 0 // PTRACE_MODE_ATTACH
    }

    /// EV_EXEC_ANON: where the executed image came from.
    pub fn exec_source(&self) -> &'static str {
        match self.aux {
            1 => "memfd",
            2 => "anon-inode",
            3 => "deleted-file",
            _ => "unknown",
        }
    }

    /// EV_MODULE: how the module was loaded.
    pub fn module_origin(&self) -> &'static str {
        match self.aux {
            1 => "init_module",
            2 => "finit_module",
            _ => "",
        }
    }

    /// EV_FILE_MODE: which setuid/setgid bit was newly gained.
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

    /// EV_FILE_MODE: degraded path resolution (bpf_d_path failed).
    pub fn degraded_path(&self) -> bool {
        self.flags & EV_F_DEGRADED_PATH != 0
    }

    /// EV_FILE_OPEN: was the file opened writable? (FMODE_WRITE)
    pub fn opened_for_write(&self) -> bool {
        self.file_mode & 0x2 != 0
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
        (38, "CAP_PERFMON"),
        (39, "CAP_BPF"),
    ];
    CAPS.iter()
        .filter(|(bit, _)| mask & (1u64 << bit) != 0)
        .map(|(_, name)| *name)
        .collect()
}
