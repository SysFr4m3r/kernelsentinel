//! Skeleton lifecycle: load the BPF object, attach the sensors, drain the ring
//! buffer.

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, Skel, SkelBuilder};
use libbpf_rs::{MapCore, RingBufferBuilder};

use std::io::Write;

use crate::event::RawEvent;
use crate::watchlist::{self, Watch};

mod skel {
    #![allow(dead_code, non_snake_case, non_camel_case_types, clippy::all)]
    include!(concat!(env!("OUT_DIR"), "/kernelsentinel.skel.rs"));
}

use skel::*;

pub struct Stats {
    pub emitted: u64,
    pub drops: u64,
    /// Events that panicked while decoding and were recovered (not aborted).
    pub decode_panics: u64,
}

/// Load, attach, and pump events into `on_event` until `stop` is set.
///
/// `on_tick` fires roughly every `tick_every` with the sensor counters read
/// live from the BPF stats map, so a caller can report liveness without a
/// second thread -- the daemon stays single-threaded, matching how graph
/// reaping is driven off the same loop. `Duration::ZERO` disables it.
pub fn run<F, T>(
    stop: &AtomicBool,
    tick_every: Duration,
    mut on_event: F,
    mut on_tick: T,
) -> Result<Stats>
where
    F: FnMut(RawEvent),
    T: FnMut(Stats),
{
    let mut open_object = MaybeUninit::uninit();
    let builder = KernelsentinelSkelBuilder::default();

    let open = builder
        .open(&mut open_object)
        .context("opening BPF object (is vmlinux.h current?)")?;
    let mut skel = open.load().context("loading BPF programs (verifier)")?;

    // Populate the watched-paths trie before attaching, so the file_open sensor
    // never runs against an empty trie (which would match nothing) or, worse,
    // a partially-filled one.
    let watches = watchlist::default_watches();
    let loaded = populate_watches(&skel.maps.watched_paths, &watches)?;

    skel.attach().context("attaching BPF programs")?;
    eprintln!("kernelsentinel: watching {loaded} paths for suspicious writes");

    // The callback runs across libbpf's C stack, where a Rust panic cannot
    // unwind and would abort the whole daemon. Catch it so a single malformed
    // event degrades to a logged error instead of taking the monitor down.
    let panics = std::cell::Cell::new(0u64);
    let mut rb = RingBufferBuilder::new();
    rb.add(&skel.maps.events, |data: &[u8]| {
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some(ev) = RawEvent::from_bytes(data) {
                on_event(ev);
            }
        }));
        if r.is_err() {
            panics.set(panics.get() + 1);
            // stderr may itself be a broken pipe; ignore the write result so
            // the recovery path can never re-panic across the C boundary.
            let _ = writeln!(
                std::io::stderr(),
                "kernelsentinel: recovered from a panic decoding one event"
            );
        }
        0
    })
    .context("registering ring buffer callback")?;
    let rb = rb.build().context("building ring buffer")?;

    let mut last_tick = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        match rb.poll(Duration::from_millis(200)) {
            Ok(()) => {}
            Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => break,
            Err(e) => return Err(e).context("polling ring buffer"),
        }
        // Driven by the poll loop, which wakes at least every 200ms whether or
        // not events arrive -- so an idle host still reports in.
        if !tick_every.is_zero() && last_tick.elapsed() >= tick_every {
            let mut s = read_stats(&skel.maps.stats);
            s.decode_panics = panics.get();
            on_tick(s);
            last_tick = std::time::Instant::now();
        }
    }

    let mut stats = read_stats(&skel.maps.stats);
    stats.decode_panics = panics.get();
    Ok(stats)
}

fn populate_watches(map: &impl MapCore, watches: &[Watch]) -> Result<usize> {
    let mut n = 0;
    for w in watches {
        let Some(key) = watchlist::encode_key(&w.prefix) else {
            eprintln!("kernelsentinel: skipping over-long watch {:?}", w.prefix);
            continue;
        };
        map.update(&key, &w.flags.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
            .with_context(|| format!("adding watch {:?}", w.prefix))?;
        n += 1;
    }
    Ok(n)
}

fn read_stats(map: &impl MapCore) -> Stats {
    let get = |idx: u32| -> u64 {
        map.lookup(&idx.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
            .ok()
            .flatten()
            .and_then(|v| {
                v.get(..8)
                    .map(|b| u64::from_ne_bytes(b.try_into().unwrap()))
            })
            .unwrap_or(0)
    };
    Stats {
        emitted: get(0),
        drops: get(1),
        decode_panics: 0,
    }
}
