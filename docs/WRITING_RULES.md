# Writing detection rules

Detections can be added in YAML, with no Rust and no recompile. A rule produces
the same kind of signal a built-in detector does, so it flows through the same
correlation, scoring, baselining, and ATT&CK mapping.

```bash
kernelsentinel rules --dir rules          # validate + list
kernelsentinel run   --rules rules        # load alongside the built-ins
kernelsentinel replay capture.ndjson --rules rules
```

Every `.yaml`/`.yml` file in the directory is one rule. Invalid rules fail
loading loudly rather than being silently skipped.

## Two rule shapes

### Single-event match

Fires a signal whenever one event satisfies all its conditions.

```yaml
name: exec_from_home
id: KS-1001            # optional; used as the signal id if present
score: 30              # base score (severity comes from correlation)
attack: [T1036]        # optional MITRE technique ids
description: executed a binary from a home directory
match:
  event: exec
  filename_prefix: /home/
```

### Sequence

Fires when an ordered series of events all occur, in a scope, within a window.

```yaml
name: escalate_then_suid
id: KS-DSL-0001
score: 55
attack: [T1068, T1548.001]
description: escalated to root then created a SUID binary
scope: same_lineage    # or same_process
within: 30s            # window from the first matched step; default 60s
sequence:
  - event: cred_change
    to_root: true
  - event: file_mode
    gained_suid: true
```

`scope`:
- `same_process` — every step on the same process.
- `same_lineage` — steps on any process in one ancestor/descendant tree (so the
  escalation on `sudo` and the `chmod` beneath it count together).

Steps are order-sensitive: list them in the order they occur at runtime.

## Event types

`exec` · `exit` · `fork` · `cred_change` · `file_open` · `file_mode` · `setcap` ·
`ptrace` · `exec_anon` · `module` · `sock_connect`

## Conditions

All conditions present on a step must hold (AND). Unknown fields are rejected at
load time.

| Field | Applies to | Meaning |
|---|---|---|
| `filename_equals` | path-bearing events | exact path/name |
| `filename_prefix` | path-bearing events | path starts with |
| `filename_contains` | path-bearing events | path contains |
| `comm_equals` | any | kernel `comm` equals (note: attacker-controlled) |
| `uid` / `euid` | any | exact real / effective uid |
| `to_root` | `cred_change` | effective uid became 0 |
| `gained_suid` | `file_mode` | a setuid/setgid bit was newly gained |
| `exec_source` | `exec_anon` | `memfd` \| `anon-inode` \| `deleted-file` |
| `in_container` | any | process is (`true`) / is not (`false`) in a container |

`filename` is the event's path where it has one (the exec target, the opened
file, the socket path, the traced process's comm for `ptrace`).

Prefer resolved fields over `comm_equals`: `comm` is truncated and
attacker-controllable (a copied `/bin/sh` runs as `.x`), which is why the
built-in detections key on the executable path, not `comm`.

## Scoring

`score` is the base contribution of the rule's signal, not the final severity.
The engine combines it with any other signals in the lineage — a chain bonus for
distinct kinds, ×1.3 rooted at a network daemon, ×1.1 inside a container — and
bands it (`<25 info · 25–49 low · 50–74 medium · 75–89 high · ≥90 critical`). A
rule that should not alert on its own belongs below 25 or in a sequence.

## Validation

`kernelsentinel rules --dir <dir>` loads every rule and reports the first error:
a rule with neither `match` nor `sequence` (or both), an unknown event type, or a
malformed `within` duration. Wire it into CI to keep a rule directory honest.

## Current limitations

- No variable binding between steps yet (e.g. linking a specific fd across
  events). Sequences correlate by scope, which covers the common lineage-shaped
  cases; per-object binding is future work.
- Sequence matching is greedy and linear — one in-flight match per (rule, scope),
  no branching or negation (`not_followed_by`) yet.
- `same_lineage` keys on the lineage's current root, which can shift if that root
  is reaped mid-sequence.
