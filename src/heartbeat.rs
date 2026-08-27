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
}

impl HeartbeatRecord {
    pub fn new(
        uptime_secs: u64,
        events: u64,
        drops: u64,
        decode_panics: u64,
        sensors_verified: Option<bool>,
        attestation_misses: u64,
    ) -> Self {
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
