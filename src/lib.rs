//! KernelSentinel core library. The `kernelsentinel` binary is a thin CLI over this.

pub mod budget;
pub mod canary;
pub mod clock;
pub mod container;
pub mod decoded;
pub mod detect;
pub mod doctor;
pub mod event;
pub mod fileid;
pub mod graph;
pub mod heartbeat;
pub mod http;
pub mod notify;
pub mod redact;
/// Live eBPF collection. Absent from a server-only build, which has no sensors
/// to run and no BPF toolchain to build them with.
#[cfg(feature = "bpf")]
pub mod sensors;
pub mod server;
pub mod watchlist;
pub mod yara;
