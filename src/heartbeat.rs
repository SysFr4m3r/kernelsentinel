//! Agent liveness and sensor telemetry.
//!
//! An incident stream alone cannot distinguish a healthy host from a dead
//! agent: both are silent. That ambiguity matters here more than in most
//! monitoring tools, because "the sensors stopped reporting" is exactly what a
//! root-level attacker produces, and it is a documented evasion for this
//! project. So the agent reports in on a timer even when it has nothing to say,
//! and the server treats a missing report as a finding rather than as calm.
//!
//! The heartbeat also carries the ring-buffer drop counter. The BPF side has
//! always counted drops; until now nothing read them, so a host quietly losing
//! events -- losing *detections* -- looked identical to one seeing everything.

use serde::{Deserialize, Serialize};

/// Wire schema tag, version-pinned like the incident record so a consumer can
/// tell the two apart on the same NDJSON stream.
pub const SCHEMA: &str = "kernelsentinel.heartbeat/v1";

/// How often the agent reports in when idle.
pub const INTERVAL_SECS: u64 = 60;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HeartbeatRecord {
    pub schema: String,
    /// Agent-side wall clock, seconds since epoch. Advisory only -- the server
    /// stamps its own receive time, because it cannot trust a host's clock.
    pub ts: u64,
    pub uptime_secs: u64,
    pub agent_version: String,
    /// Events the sensors pushed into the ring buffer since start.
    pub events: u64,
    /// Ring-buffer drops since start. Every drop is a missed detection.
    pub drops: u64,
    /// Events that panicked while decoding and were recovered.
    pub decode_panics: u64,
    /// Whether the agent confirmed its sensors are still watching, by execing a
    /// child and checking it observed the exec. `None` until the first round
    /// completes -- an unanswered question is not a failure.
    ///
    /// This is the difference between "the agent is alive" and "the agent can
    /// see": root can detach a BPF link from under a running process, leaving
    /// it heartbeating happily while blind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensors_verified: Option<bool>,
    /// Attestation rounds where the canary was never observed.
    #[serde(default)]
    pub attestation_misses: u64,
    /// Sensors that can observe an event, out of how many exist.
    ///
    /// Distinct from `sensors_verified`, which is the canary and speaks only for
    /// `exec`. A host can pass attestation with six of its eleven sensors inert
    /// -- that is the ordinary state on any distribution shipping BPF-LSM
    /// compiled in but not enabled -- and without these the fleet view has no
    /// way to tell it apart from one seeing everything.
    ///
    /// Zero means an agent too old to report it, not a host with no sensors:
    /// such an agent could not have started at all, since exec is mandatory.
    #[serde(default)]
    pub sensors_active: u32,
    #[serde(default)]
    pub sensors_total: u32,
}

/// What the sensors have counted, as one value.
///
/// Grouped rather than passed as six positional integers: every one of them is
/// a number, so a transposed pair compiles cleanly and reports the wrong thing
/// forever. `sensors::Stats` cannot be used here because it lives behind the
/// `bpf` feature and this type has to exist in a server-only build.
#[derive(Clone, Copy, Default)]
pub struct Counters {
    pub events: u64,
    pub drops: u64,
    pub decode_panics: u64,
    /// Sensors that can observe an event, out of how many exist.
    pub sensors_active: u32,
    pub sensors_total: u32,
}

impl HeartbeatRecord {
    pub fn new(
        uptime_secs: u64,
        counters: Counters,
        sensors_verified: Option<bool>,
        attestation_misses: u64,
    ) -> Self {
        let Counters {
            events,
            drops,
            decode_panics,
            sensors_active,
            sensors_total,
        } = counters;
        Self {
            schema: SCHEMA.to_string(),
            ts: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            uptime_secs,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            events,
            drops,
            decode_panics,
            sensors_verified,
            attestation_misses,
            sensors_active,
            sensors_total,
        }
    }

    pub fn to_ndjson(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|e| format!(r#"{{"error":"{e}"}}"#))
    }

    /// True if a parsed NDJSON line is a heartbeat rather than an incident.
    pub fn is_heartbeat(v: &serde_json::Value) -> bool {
        v.get("schema").and_then(|s| s.as_str()) == Some(SCHEMA)
    }
}
