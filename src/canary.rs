//! Active self-attestation.
//!
//! The heartbeat proves the agent process is alive. It does not prove the
//! sensors are still attached, and those are different failures: root with
//! CAP_BPF can detach a BPF link out from under a running process, after which
//! the agent keeps heartbeating and the panel keeps showing a healthy host that
//! is in fact completely blind. That is worse than a dead agent, because a dead
//! agent is visible.
//!
//! So the agent does something it must observe, and checks that it did. Each
//! interval it execs a trivial child; if the exec sensor is attached, an event
//! for that pid arrives. If the previous interval's child was never seen, the
//! sensors are not watching and the heartbeat says so.
//!
//! Passive checks cannot cover this. "Have any events arrived recently" is a
//! guess on a quiet host, and querying our own link fds tells us the file
//! descriptor is open, not that the program is still attached.

use std::cell::Cell;
use std::process::{Command, Stdio};

pub struct Canary {
    /// The child spawned last interval, awaiting confirmation.
    pending: Cell<Option<u32>>,
    /// Whether that child's exec was observed.
    seen: Cell<bool>,
    /// Result of the most recently completed round. None until the first
    /// round finishes -- an unanswered question is not a failure.
    verified: Cell<Option<bool>>,
    /// Rounds where the canary was never observed.
    misses: Cell<u64>,
}

impl Default for Canary {
    fn default() -> Self {
        Self::new()
    }
}

impl Canary {
    pub fn new() -> Self {
        Self {
            pending: Cell::new(None),
            seen: Cell::new(false),
            verified: Cell::new(None),
            misses: Cell::new(0),
        }
    }

    /// Call for every observed exec. Cheap: one comparison against a `Cell`.
    pub fn observe(&self, tgid: u32) {
        if self.pending.get() == Some(tgid) {
            self.seen.set(true);
        }
    }

    /// Close the previous round and open a new one. Returns the previous
    /// round's verdict, or None if there was no previous round.
    ///
    /// A full interval separates spawn from check, so a slow ring buffer is
    /// never mistaken for a detached sensor.
    pub fn round(&self) -> Option<bool> {
        if self.pending.get().is_some() {
            let ok = self.seen.get();
            self.verified.set(Some(ok));
            if !ok {
                self.misses.set(self.misses.get() + 1);
            }
        }
        self.seen.set(false);
        self.pending.set(self.spawn());
        self.verified.get()
    }

    pub fn misses(&self) -> u64 {
        self.misses.get()
    }

    /// Exec something harmless and return its pid. `/bin/true` is chosen for
    /// being universally present and doing nothing; the point is the exec
    /// itself, which is what the sensor must see.
    fn spawn(&self) -> Option<u32> {
        let child = Command::new("/bin/true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        match child {
            Ok(mut c) => {
                let pid = c.id();
                // Reap it rather than leaving a zombie every interval.
                std::thread::spawn(move || {
                    let _ = c.wait();
                });
                Some(pid)
            }
            // If we cannot spawn, we cannot attest. Report unknown rather than
            // claiming the sensors failed -- that would be a false alarm about
            // the wrong thing.
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_verdict_before_the_first_round_completes() {
        let c = Canary::new();
        // First round only spawns; there is nothing yet to have missed.
        assert_eq!(c.round(), None, "an unanswered question is not a failure");
        assert_eq!(c.misses(), 0);
    }

    #[test]
    fn a_seen_canary_verifies() {
        let c = Canary::new();
        c.round();
        let pid = c.pending.get().expect("a child should have been spawned");
        c.observe(pid);
        assert_eq!(c.round(), Some(true));
        assert_eq!(c.misses(), 0);
    }

    /// The case this exists for: the agent is alive and spawning, but its own
    /// exec is never observed, so the sensors are not watching.
    #[test]
    fn an_unseen_canary_reports_blind() {
        let c = Canary::new();
        c.round();
        // observe() is never called -- the sensor saw nothing.
        assert_eq!(c.round(), Some(false));
        assert_eq!(c.misses(), 1);
    }

    #[test]
    fn an_unrelated_exec_does_not_verify() {
        let c = Canary::new();
        c.round();
        let pid = c.pending.get().unwrap();
        c.observe(pid.wrapping_add(1));
        assert_eq!(c.round(), Some(false), "only our own child counts");
    }

    #[test]
    fn misses_accumulate_across_rounds() {
        let c = Canary::new();
        c.round();
        for _ in 0..3 {
            c.round();
        }
        assert_eq!(c.misses(), 3);
    }

    #[test]
    fn recovery_is_reported() {
        let c = Canary::new();
        c.round();
        assert_eq!(c.round(), Some(false));
        let pid = c.pending.get().unwrap();
        c.observe(pid);
        assert_eq!(c.round(), Some(true), "a later round must be able to pass");
        assert_eq!(c.misses(), 1, "the earlier miss still counts");
    }
}
