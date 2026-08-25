//! Brute-force protection for the login endpoint.
//!
//! argon2 makes guessing slow, not impossible, and "slow" is a poor defence
//! when nothing is counting. This counts.
//!
//! Keyed on the peer address, deliberately not on the username. Locking a
//! username out would hand any anonymous caller a way to keep the real admin
//! out of their own panel during an incident -- turning a login form into a
//! denial-of-service primitive against the people responding.
//!
//! The peer address is the TCP socket's, never `X-Forwarded-For`: a header the
//! caller controls is a header the caller can vary, which would make the limit
//! decorative. Behind a reverse proxy every request therefore shares the
//! proxy's address, and the limit becomes global rather than per-client -- safe
//! but blunt, and worth knowing before putting one in front.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Failures tolerated inside `WINDOW` before a lockout starts.
pub const MAX_FAILURES: u32 = 5;
/// Failures older than this stop counting, so ordinary fat-fingering by a
/// legitimate admin never accumulates into a lockout.
pub const WINDOW: Duration = Duration::from_secs(300);
/// How long a locked-out address stays locked out.
pub const LOCKOUT: Duration = Duration::from_secs(900);
/// Ceiling on tracked addresses, so a distributed attempt cannot grow this map
/// without bound. Expired entries are dropped first.
const MAX_TRACKED: usize = 10_000;

struct Attempt {
    failures: u32,
    first: Instant,
    locked_until: Option<Instant>,
}

#[derive(Default)]
pub struct LoginLimiter {
    seen: Mutex<HashMap<IpAddr, Attempt>>,
}

impl LoginLimiter {
    /// Seconds remaining before this address may try again, or `None` if it may
    /// try now.
    pub fn locked_for(&self, ip: IpAddr) -> Option<u64> {
        let now = Instant::now();
        let seen = self.seen.lock().unwrap();
        let a = seen.get(&ip)?;
        let until = a.locked_until?;
        (until > now).then(|| (until - now).as_secs().max(1))
    }

    /// Record a failed attempt. Returns the lockout in seconds if this one
    /// tripped it.
    pub fn record_failure(&self, ip: IpAddr) -> Option<u64> {
        let now = Instant::now();
        let mut seen = self.seen.lock().unwrap();
        Self::evict(&mut seen, now);

        let a = seen.entry(ip).or_insert(Attempt {
            failures: 0,
            first: now,
            locked_until: None,
        });
        // A window that has rolled over starts a fresh count, so slow, spread
        // out typos never add up to a lockout.
        if now.duration_since(a.first) > WINDOW {
            a.failures = 0;
            a.first = now;
            a.locked_until = None;
        }
        a.failures += 1;
        if a.failures >= MAX_FAILURES {
            a.locked_until = Some(now + LOCKOUT);
            return Some(LOCKOUT.as_secs());
        }
        None
    }

    /// A successful login clears the address: the counter exists to slow down
    /// guessing, not to punish someone who eventually typed it right.
    pub fn record_success(&self, ip: IpAddr) {
        self.seen.lock().unwrap().remove(&ip);
    }

    fn evict(seen: &mut HashMap<IpAddr, Attempt>, now: Instant) {
        seen.retain(|_, a| {
            a.locked_until.is_some_and(|u| u > now) || now.duration_since(a.first) <= WINDOW
        });
        if seen.len() > MAX_TRACKED {
            // Still oversized after dropping expired entries: keep the locked
            // ones, which are the ones that matter.
            seen.retain(|_, a| a.locked_until.is_some_and(|u| u > now));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn lockout_trips_only_after_the_threshold() {
        let l = LoginLimiter::default();
        let a = ip("10.0.0.1");
        for i in 1..MAX_FAILURES {
            assert!(l.record_failure(a).is_none(), "failure {i} must not lock");
            assert!(l.locked_for(a).is_none());
        }
        assert!(l.record_failure(a).is_some(), "the threshold must lock");
        let left = l.locked_for(a).expect("must now be locked");
        assert!(left > 0 && left <= LOCKOUT.as_secs());
    }

    #[test]
    fn success_clears_the_counter() {
        let l = LoginLimiter::default();
        let a = ip("10.0.0.2");
        l.record_failure(a);
        l.record_failure(a);
        l.record_success(a);
        // The count restarted, so the next few failures must not lock.
        for _ in 1..MAX_FAILURES {
            assert!(l.record_failure(a).is_none());
        }
    }

    /// One address must not be able to lock another out.
    #[test]
    fn lockout_is_scoped_to_one_address() {
        let l = LoginLimiter::default();
        let attacker = ip("10.0.0.3");
        let admin = ip("10.0.0.4");
        for _ in 0..MAX_FAILURES {
            l.record_failure(attacker);
        }
        assert!(l.locked_for(attacker).is_some());
        assert!(
            l.locked_for(admin).is_none(),
            "an unrelated address must be unaffected"
        );
    }

    #[test]
    fn ipv6_is_tracked_separately() {
        let l = LoginLimiter::default();
        let v6 = ip("2001:db8::1");
        for _ in 0..MAX_FAILURES {
            l.record_failure(v6);
        }
        assert!(l.locked_for(v6).is_some());
        assert!(l.locked_for(ip("10.0.0.9")).is_none());
    }

    #[test]
    fn expired_entries_are_evicted() {
        let l = LoginLimiter::default();
        let mut seen = l.seen.lock().unwrap();
        let stale = Instant::now() - (WINDOW + Duration::from_secs(60));
        seen.insert(
            ip("10.1.1.1"),
            Attempt {
                failures: 3,
                first: stale,
                locked_until: None,
            },
        );
        LoginLimiter::evict(&mut seen, Instant::now());
        assert!(seen.is_empty(), "a stale, unlocked entry must be dropped");
    }

    /// A lockout must survive eviction, or the cleanup would hand an attacker
    /// their reset.
    #[test]
    fn eviction_keeps_active_lockouts() {
        let l = LoginLimiter::default();
        let a = ip("10.1.1.2");
        for _ in 0..MAX_FAILURES {
            l.record_failure(a);
        }
        {
            let mut seen = l.seen.lock().unwrap();
            LoginLimiter::evict(&mut seen, Instant::now());
        }
        assert!(
            l.locked_for(a).is_some(),
            "the lockout must survive eviction"
        );
    }
}
