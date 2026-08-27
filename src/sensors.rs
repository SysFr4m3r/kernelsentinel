//! Skeleton lifecycle: load the BPF object, attach the sensors, drain the ring
//! buffer.

use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
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
/// The first line of a multi-line error, for a one-line log.
fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or(s)
}

/// Enforcement policy, mirroring `enum` values in bpf/events.h.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Enforce {
    /// Detect only. The default, and what every LSM hook did before M7.
    Off,
    /// Report what would be blocked, block nothing.
    Audit,
    /// Actually deny.
    On,
}

impl Enforce {
    fn mode(self) -> u32 {
        match self {
            Enforce::Off => 0,
            Enforce::Audit => 1,
            Enforce::On => 2,
        }
    }
}

pub fn run<F, T>(
    stop: &AtomicBool,
    tick_every: Duration,
    enforce: Enforce,
    host_mnt_ns: u32,
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
    let skel = open.load().context("loading BPF programs (verifier)")?;

    // Populate the watched-paths trie before attaching, so the file_open sensor
    // never runs against an empty trie (which would match nothing) or, worse,
    // a partially-filled one.
    let watches = watchlist::default_watches();
    let loaded = populate_watches(&skel.maps.watched_paths, &watches)?;

    // Written before attach, so no hook can ever observe a half-configured
    // policy. Denial also requires a known host namespace: without a reference
    // there is no way to tell "in a container" from "is the host", and the
    // failure mode of guessing is denying on the host itself.
    if enforce != Enforce::Off && host_mnt_ns == 0 {
        anyhow::bail!(
            "enforcement needs the host mount namespace, which could not be read from \
             /proc/1/ns/mnt; refusing to arm denial without it"
        );
    }
    // Escape hatches are matched by identity, not path: an escape reaches them
    // through a bind mount at some other location, where no watched prefix
    // applies. Populated before attach so no open can slip past a partial map.
    let hatches = watchlist::escape_hatch_ids();
    for (dev, ino) in &hatches {
        // struct file_id { u64 ino; u32 dev; u32 _pad; }
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&ino.to_ne_bytes());
        key[8..12].copy_from_slice(&(*dev as u32).to_ne_bytes());
        skel.maps
            .escape_targets
            .update(&key, &1u32.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
            .context("populating the escape-target map")?;
    }
    eprintln!(
        "kernelsentinel: tracking {} kernel escape hatch(es) by file identity",
        hatches.len()
    );

    let cfg = [enforce.mode().to_ne_bytes(), host_mnt_ns.to_ne_bytes()].concat();
    skel.maps
        .enforce
        .update(&0u32.to_ne_bytes(), &cfg, libbpf_rs::MapFlags::ANY)
        .context("writing the enforcement config")?;

    // Attach one program at a time rather than all-or-nothing.
    //
    // skel.attach() fails the whole load if any single program cannot attach,
    // and the ones that fail on a given kernel are predictable: BPF-LSM is off
    // by default on RHEL, Rocky and older Debian/Ubuntu, so every lsm/ hook
    // fails there. All-or-nothing turns "five of eleven sensors work" into
    // "the agent refuses to start", which is the wrong trade for a monitoring
    // tool -- partial visibility beats none, as long as it says which part.
    let mut links = Vec::new();
    let mut attached: Vec<&str> = Vec::new();
    let mut missing: Vec<(&str, String)> = Vec::new();
    macro_rules! attach {
        ($prog:ident, $name:literal) => {
            match skel.progs.$prog.attach() {
                Ok(l) => {
                    links.push(l);
                    attached.push($name);
                }
                Err(e) => missing.push(($name, e.to_string())),
            }
        };
    }
    attach!(handle_exec, "exec");
    attach!(handle_fork, "fork");
    attach!(handle_exit, "exit");
    attach!(handle_commit_creds, "commit_creds");
    attach!(handle_file_open, "file_open");
    attach!(handle_path_chmod, "path_chmod");
    attach!(handle_setxattr, "inode_setxattr");
    attach!(handle_ptrace, "ptrace");
    attach!(handle_bprm, "bprm_check");
    attach!(handle_module, "module_load");
    attach!(handle_socket_connect, "socket_connect");

    // exec is not optional: without it there is no process graph, and every
    // detection is an attribution to a process we never saw start.
    if !attached.contains(&"exec") {
        anyhow::bail!(
            "the exec sensor could not attach, so there is no process graph to \
             build on; run `kernelsentinel doctor` to see what this kernel supports"
        );
    }
    eprintln!(
        "kernelsentinel: {} of {} sensors attached",
        attached.len(),
        attached.len() + missing.len()
    );
    if !missing.is_empty() {
        // Named, not counted. "6/11 attached" leaves an operator guessing which
        // detections are silently unavailable on their host.
        for (name, err) in &missing {
            eprintln!(
                "kernelsentinel:   unavailable: {name} ({})",
                first_line(err)
            );
        }
        eprintln!(
            "kernelsentinel:   detections relying on those sensors will not fire on this kernel"
        );
    }
    match enforce {
        Enforce::Off => {}
        Enforce::Audit => eprintln!(
            "kernelsentinel: enforcement AUDIT -- reporting what would be denied, blocking nothing"
        ),
        Enforce::On => eprintln!(
            "kernelsentinel: enforcement ON -- kernel escape-hatch writes from outside the host \
             mount namespace will be denied"
        ),
    }
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
