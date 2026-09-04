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

/// Sensors whose BPF programs are `lsm/` hooks.
///
/// They attach on any kernel with BPF-LSM compiled in, but the kernel only
/// invokes the hook when `bpf` is in `/sys/kernel/security/lsm`. Without that
/// they are attached and permanently silent, which is why they are not counted
/// as available. Kept in step with the BPF source by the test at the bottom of
/// this file.
/// How often `/home` is re-enumerated for accounts created after startup.
///
/// Short because the gap it closes is a persistence vector -- an account created
/// now has an `authorized_keys` that nothing watches until this runs -- and the
/// work is a single readdir.
const WATCH_REFRESH: Duration = Duration::from_secs(15);

const LSM_SENSORS: &[&str] = &[
    "file_open",
    "path_chmod",
    "path_mknod",
    "inode_setxattr",
    "ptrace",
    "bprm_check",
    "unix_connect",
];

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
    /// Sensors that can actually observe an event, and how many exist.
    ///
    /// Carried on every tick so the fleet server learns it without a second
    /// message type. A host reporting 5 of 11 is not blind -- the canary still
    /// attests that exec works -- but it cannot see most of what this tool
    /// detects, and a panel that shows it as an unqualified green is telling
    /// the operator something false by omission.
    pub sensors_active: u32,
    pub sensors_total: u32,
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
    // Remembered so the periodic refresh below can tell a new home directory
    // from one already covered, and report only what it added.
    let mut watched_prefixes: std::collections::HashSet<String> =
        watches.iter().map(|w| w.prefix.clone()).collect();

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
    for id in &hatches {
        skel.maps
            .escape_targets
            .update(
                &id.to_map_key(),
                &1u32.to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            )
            .context("populating the escape-target map")?;
    }
    eprintln!(
        "kernelsentinel: tracking {} kernel escape hatch(es) by file identity",
        hatches.len()
    );

    // The same files the trie watches, also keyed by identity, so a second name
    // for one is still recognised. `ln /etc/shadow /root/.x && cat /root/.x`
    // read every hash on the host and produced no event at all until this
    // existed -- the trie can only compare the name the opener chose.
    let watched_ids = watchlist::watched_file_ids();
    for (id, flags) in &watched_ids {
        skel.maps
            .watched_ids
            .update(
                &id.to_map_key(),
                &flags.to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            )
            .context("populating the watched-identity map")?;
    }
    eprintln!(
        "kernelsentinel: {} watched file(s) also matched by identity, so a hard link \
         or bind mount to one is still seen",
        watched_ids.len()
    );

    let cfg = [enforce.mode().to_ne_bytes(), host_mnt_ns.to_ne_bytes()].concat();
    skel.maps
        .enforce
        .update(&0u32.to_ne_bytes(), &cfg, libbpf_rs::MapFlags::ANY)
        .context("writing the enforcement config")?;

    // Attach one program at a time rather than all-or-nothing.
    //
    // skel.attach() fails the whole load if any single program cannot attach.
    // All-or-nothing turns "five of eleven sensors work" into "the agent refuses
    // to start", which is the wrong trade for a monitoring tool -- partial
    // visibility beats none, as long as it says which part.
    //
    // This used to say the lsm/ hooks "fail" on a kernel without BPF-LSM. They
    // do not. Measured on an Ubuntu runner with `bpf` absent from
    // /sys/kernel/security/lsm: all eleven attached, and a real `chmod u+s` and
    // a real read of /etc/shadow produced nothing at all. The kernel accepts an
    // lsm/ program whether or not the bpf LSM is active; only the hook being
    // invoked depends on it. Attach failure is therefore not how this
    // degradation shows up, and counting attachments reported eleven working
    // sensors on a host with five. See the LSM_SENSORS adjustment below.
    let mut links = Vec::new();
    let mut attached: Vec<&str> = Vec::new();
    // Sensors whose programs are `lsm/` hooks, and therefore inert without the
    // bpf LSM. Kept in step with the BPF source by
    // sensors::tests::lsm_sensor_list_matches_the_bpf_source.
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
    attach!(handle_path_mknod, "path_mknod");
    attach!(handle_setxattr, "inode_setxattr");
    attach!(handle_ptrace, "ptrace");
    attach!(handle_bprm, "bprm_check");
    attach!(handle_module, "module_load");
    attach!(handle_unix_connect, "unix_connect");

    // A successful attach is not a working sensor. If the bpf LSM is not in the
    // kernel's active list, every lsm/ program is attached to a hook the kernel
    // will never call, so report them as unavailable rather than counting them.
    //
    // Reporting the truth here costs a host nothing it actually had, and the
    // alternative is an operator reading "11 of 11 sensors attached" and
    // believing the file, credential-theft, fileless-exec and container-socket
    // detections are watching. They are not.
    if crate::doctor::bpf_lsm_active() == Some(false) {
        let inert: Vec<&str> = attached
            .iter()
            .copied()
            .filter(|n| LSM_SENSORS.contains(n))
            .collect();
        attached.retain(|n| !LSM_SENSORS.contains(n));
        for name in inert {
            missing.push((
                name,
                "attached, but `bpf` is not in /sys/kernel/security/lsm, so the kernel never \
                 invokes the hook"
                    .to_string(),
            ));
        }
    }

    // exec is not optional: without it there is no process graph, and every
    // detection is an attribution to a process we never saw start.
    if !attached.contains(&"exec") {
        anyhow::bail!(
            "the exec sensor could not attach, so there is no process graph to \
             build on; run `kernelsentinel doctor` to see what this kernel supports"
        );
    }
    let sensors_active = attached.len() as u32;
    let sensors_total = (attached.len() + missing.len()) as u32;
    eprintln!("kernelsentinel: {sensors_active} of {sensors_total} sensors active");
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
    // Enforcement is implemented by the file_open program returning -EPERM. If
    // that program is not live, nothing can be denied and no amount of policy
    // in the map changes it.
    //
    // Saying "will be denied" here regardless is the worst assurance this tool
    // could give: an operator who armed `--enforce on` believes container
    // escapes are blocked, stops worrying about them, and is not protected. The
    // sensor-count bug was a monitoring gap; this one would be a security
    // control that exists only in the log line announcing it.
    //
    // Unlike an unknown host namespace this does not bail. That case risks
    // denying on the host, which is an actively harmful wrong action; this one
    // risks not denying, which is a gap -- and refusing to start would also
    // throw away the five sensors that do work. So enforcement is disarmed, the
    // map is rewritten to OFF so nothing downstream reads a policy that cannot
    // be applied, and the operator is told plainly.
    let mut enforce = enforce;
    if enforce != Enforce::Off && !attached.contains(&"file_open") {
        eprintln!(
            "kernelsentinel: enforcement REQUESTED BUT NOT ARMED -- it is the file_open sensor \
             that denies, and that sensor is not active on this kernel. Nothing will be blocked. \
             Enable BPF-LSM (see docs/COMPATIBILITY.md) and restart to arm it."
        );
        enforce = Enforce::Off;
        let cfg = [enforce.mode().to_ne_bytes(), host_mnt_ns.to_ne_bytes()].concat();
        skel.maps
            .enforce
            .update(&0u32.to_ne_bytes(), &cfg, libbpf_rs::MapFlags::ANY)
            .context("disarming the enforcement config")?;
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

    // The ready signal, and the only line that means what it says: every
    // program is attached, the maps are populated and the ring buffer is built,
    // so from here an event that happens is an event that is seen.
    //
    // It exists because the message that used to serve this purpose was printed
    // by main() *before* sensors::run was even called. Two harnesses waited on
    // it -- the attack suite, under a comment about how a scenario running
    // before the hooks attach looks exactly like a missed detection, and the
    // benchmark, which would have started its load against nothing.
    eprintln!("kernelsentinel: ready, streaming events (ctrl-c to stop)");

    let mut last_tick = std::time::Instant::now();
    let mut last_watch_refresh = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        match rb.poll(Duration::from_millis(200)) {
            Ok(()) => {}
            Err(e) if e.kind() == libbpf_rs::ErrorKind::Interrupted => break,
            Err(e) => return Err(e).context("polling ring buffer"),
        }
        // Driven by the poll loop, which wakes at least every 200ms whether or
        // not events arrive -- so an idle host still reports in.
        // A home directory created after startup has an authorized_keys nobody
        // is watching, and the daemon runs for weeks. Measured before this:
        // useradd followed by writing authorized_keys produced no
        // authorized_keys_write at all.
        //
        // On its own cadence rather than the heartbeat's, because the heartbeat
        // is a minute and that is a long time to leave a fresh account
        // unwatched. The work is one readdir of /home, so four a minute costs
        // nothing worth measuring.
        if last_watch_refresh.elapsed() >= WATCH_REFRESH {
            last_watch_refresh = std::time::Instant::now();
            let fresh: Vec<Watch> = watchlist::home_watches()
                .into_iter()
                .filter(|w| !watched_prefixes.contains(&w.prefix))
                .collect();
            if !fresh.is_empty() {
                match populate_watches(&skel.maps.watched_paths, &fresh) {
                    Ok(n) => {
                        for w in &fresh {
                            watched_prefixes.insert(w.prefix.clone());
                        }
                        eprintln!("kernelsentinel: now also watching {n} new path(s) under /home");
                    }
                    // A full trie is worth saying out loud once rather than on
                    // every tick, but it must not stop the event loop.
                    Err(e) => eprintln!("kernelsentinel: could not add new home watches: {e}"),
                }
            }
        }

        if !tick_every.is_zero() && last_tick.elapsed() >= tick_every {
            let mut s = read_stats(&skel.maps.stats);
            s.decode_panics = panics.get();
            s.sensors_active = sensors_active;
            s.sensors_total = sensors_total;
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
        sensors_active: 0,
        sensors_total: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::LSM_SENSORS;

    /// A sensor added as an `lsm/` program but left out of `LSM_SENSORS` would
    /// be counted as available on a kernel where it can never fire -- the exact
    /// false assurance this list exists to prevent, reintroduced quietly.
    #[test]
    fn lsm_sensor_list_matches_the_bpf_source() {
        let mut found = 0usize;
        for entry in std::fs::read_dir("bpf/sensors").expect("bpf/sensors") {
            let path = entry.expect("dir entry").path();
            let src = std::fs::read_to_string(&path).expect("sensor source");
            found += src.matches("SEC(\"lsm/").count();
        }
        assert_eq!(
            found,
            LSM_SENSORS.len(),
            "bpf/sensors declares {found} lsm/ programs but LSM_SENSORS names {}. \
             Add it to the list, or it will be counted as working on a kernel \
             where the hook is never invoked.",
            LSM_SENSORS.len()
        );
    }
}
