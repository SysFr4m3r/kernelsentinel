//! KernelSentinel core library. The `kernelsentinel` binary is a thin CLI over this.

pub mod clock;
pub mod container;
pub mod decoded;
pub mod detect;
pub mod doctor;
pub mod event;
pub mod graph;
pub mod heartbeat;
pub mod http;
pub mod notify;
pub mod redact;
pub mod sensors;
pub mod server;
pub mod watchlist;
pub mod yara;
