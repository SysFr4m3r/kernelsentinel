//! Kernel events are timestamped with CLOCK_BOOTTIME. Compute the offset to
//! wall-clock once at startup so alerts can be printed with real times.

use std::time::{Duration, SystemTime};

pub struct BootClock {
    /// Wall-clock time corresponding to boottime == 0.
    epoch: SystemTime,
}

impl Default for BootClock {
    fn default() -> Self {
        Self::new()
    }
}

impl BootClock {
    pub fn new() -> Self {
        let boot = clock_gettime(libc::CLOCK_BOOTTIME);
        let now = SystemTime::now();
        Self {
            epoch: now.checked_sub(boot).unwrap_or(SystemTime::UNIX_EPOCH),
        }
    }

    /// A clock that renders a boot-clock timestamp as time-since-boot, not
    /// wall-clock. For replaying a capture: the original wall-clock offset is not
    /// recorded, so mapping the capture's boot timestamps through THIS machine's
    /// boot epoch would print plausible-looking but wrong times. Boot-relative is
    /// honest and identical on every machine that replays the same capture.
    pub fn boot_relative() -> Self {
        Self {
            epoch: SystemTime::UNIX_EPOCH,
        }
    }

    pub fn to_wall(&self, ts_ns: u64) -> SystemTime {
        self.epoch + Duration::from_nanos(ts_ns)
    }

    /// Milliseconds since the Unix epoch, for shipping a timestamp somewhere
    /// that has no idea when this host booted. A boot-relative number is
    /// meaningless off-box: only the agent knows its own boot epoch.
    pub fn to_epoch_ms(&self, ts_ns: u64) -> u64 {
        self.to_wall(ts_ns)
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// `HH:MM:SS.mmm` in UTC, without pulling in a date-time crate for M0.
    pub fn format(&self, ts_ns: u64) -> String {
        let d = self
            .to_wall(ts_ns)
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = d.as_secs();
        let ms = d.subsec_millis();
        format!(
            "{:02}:{:02}:{:02}.{:03}",
            (secs / 3600) % 24,
            (secs / 60) % 60,
            secs % 60,
            ms
        )
    }
}

fn clock_gettime(clk: libc::clockid_t) -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is a valid, properly aligned timespec for the duration of the call.
    unsafe { libc::clock_gettime(clk, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}
