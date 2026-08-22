//! Skeleton lifecycle: load the BPF object, attach the sensors, drain the ring
//! buffer.

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, RingBufferBuilder};

use crate::event::RawEvent;

mod skel {
    #![allow(dead_code, non_snake_case, non_camel_case_types, clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/kernelsentinel.skel.rs"));
}

use skel::*;

pub struct Stats {
    pub emitted: u64,
    pub drops: u64,
}

/// Load, attach, and pump events into `on_event` until `stop` is set.
pub fn run<F>(stop: Arc<AtomicBool>, mut on_event: F) -> Result<Stats>
where
    F: FnMut(RawEvent),
{
    let mut open_object = MaybeUninit::uninit();
    let builder = KernelsentinelSkelBuilder::default();

    let open = builder
        .open(&mut open_object)
        .context("opening BPF object (is vmlinux.h current?)")?;
    let mut skel = open.load().context("loading BPF programs (verifier)")?;
    skel.attach().context("attaching BPF programs")?;

    let mut rb = RingBufferBuilder::new();
    rb.add(&skel.maps.events, move |data: &[u8]| {
        if let Some(ev) = RawEvent::from_bytes(data) {
            on_event(ev);
        }
        0
    })
    .context("registering ring buffer callback")?;
    let rb = rb.build().context("building ring buffer")?;

    while !stop.load(Ordering::Relaxed) {
        match rb.poll(Duration::from_millis(200)) {
            Ok(()) => {}
            Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => break,
            Err(e) => return Err(e).context("polling ring buffer"),
        }
    }

    Ok(read_stats(&skel.maps.stats))
}

fn read_stats(map: &impl MapCore) -> Stats {
    let get = |idx: u32| -> u64 {
        map.lookup(&idx.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
            .ok()
            .flatten()
            .and_then(|v| v.get(..8).map(|b| u64::from_ne_bytes(b.try_into().unwrap())))
            .unwrap_or(0)
    };
    Stats {
        emitted: get(0),
        drops: get(1),
    }
}
