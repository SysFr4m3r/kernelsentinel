# Performance

What the agent costs, and where it starts losing events.

Numbers come from the agent's own counters — the same ones it ships in every
heartbeat — not from anything the benchmark infers. Reproduce them with:

```bash
sudo scripts/bench.sh
```

## What is measured

| | |
|---|---|
| **events/sec** | events the sensors delivered to userspace |
| **drops** | events the ring buffer could not hold — **missed detections** |
| **cpu%** | agent CPU over the run, excluding the `/proc` bootstrap at startup |
| **rss MB** | peak resident set of the agent process |

Three loads. **idle** is the machine doing its normal background work, which is
what a real host mostly looks like. **moderate** paces one process spawn every
10ms. **saturate** runs one unpaced spawn loop per core, to find the ceiling.

Each `exec` produces roughly three events — fork, exec, exit — so the event rate
is about three times the spawn rate.

## Results

<!-- BENCH:START -->
Measured on an 8-core desktop, kernel 7.0.12, 20s per mode.

| mode | events | events/sec | drops | drop% | cpu% | rss MB |
|---|---|---|---|---|---|---|
| idle | 780 | 37 | 0 | 0.00% | **0.2%** | 26.6 |
| moderate | 4,702 | 235 | 0 | 0.00% | 1.4% | 27.6 |
| 1 spawner | 41,249 | 2,062 | 0 | 0.00% | 6.4% | 30.7 |
| 2 spawners | 78,285 | 3,914 | 0 | 0.00% | 8.3% | 35.4 |
| 4 spawners | 165,246 | 8,262 | 0 | 0.00% | 10.0% | 46.9 |
| 8 spawners | 233,339 | 11,667 | 180,651 | **43.64%** | 47.5% | 64.7 |

`cpu%` is of a single core; the agent is single-threaded, so 100% is its ceiling.

**Idle cost is 0.2% of one core and 27 MB.** That is what most hosts sit at, and
it is the number that decides whether anyone leaves the agent running.

**8,262 events/sec sustained with zero loss, at 10% of one core.** There is a
great deal of headroom below that: the cost curve is close to linear from 37 to
8,262 events/sec, and nothing is dropped anywhere along it.

## The cliff is contention, not throughput

The jump from 4 to 8 spawners is not a throughput limit being reached. Events
only rose 41% (8,262 to 11,667) while CPU rose 375% (10% to 47.5%) and 43.6% of
events were lost.

The machine has 8 cores. At 8 spawners the workload occupies all of them, and
the agent — single-threaded — has to compete for the core it needs to drain the
ring buffer. It does not get scheduled often enough, the buffer fills, and the
kernel discards.

So the honest characterisation is not "the ceiling is ~8,000 events/sec". It is:

> Loss begins when the workload leaves the agent no core to run on, not at a
> particular event rate.

That distinction matters for deployment. A busy build server with work sized to
its core count has headroom; one that runs `make -j$(nproc)` with nothing held
back can starve the agent, and the drop counter is how you find out. A host
reporting non-zero drops is never presented as fully covered in the panel.

## Caveat on the benchmark itself

The saturation row measures the agent *and this benchmark's own workload*
competing for CPU. It therefore describes contention as much as agent capacity.
Isolating them properly — pinning the agent to a reserved core, or generating
load from another machine — would give a truer ceiling, and has not been done.
<!-- BENCH:END -->

## How to read a drop

A drop is not a slow path or a queued event; it is an event the kernel produced
and the agent never saw. Detections that depended on it did not fire, and
nothing downstream can tell the difference between "nothing happened" and "we
missed it".

That is why the number worth quoting is not peak throughput but **the rate at
which drops begin**. Above it, coverage is no longer complete, and the panel
says so: a host reporting a non-zero drop count is never presented as fully
covered.

The ring buffer is 8 MB. Raising it trades memory for headroom; the drop counter
is how you decide whether that trade is needed on a given host.

## Caveats

Measured on one machine, on one kernel. A host with a different core count,
kernel version, or workload shape will differ — the point of shipping the
benchmark rather than only its output is that you can measure your own.

The synthetic saturation load is exec-heavy because that is the cheapest way to
generate a high event rate. A workload that is heavy on *watched file writes*
would stress a different path, and is not covered here.

**These numbers were taken before a starting-line bug was fixed.** `bench.sh`
waited for a log line that the agent printed *before* attaching its sensors, so
the load could begin a fraction of a second early and some of its events were
generated while nothing was watching. That direction under-counts — it makes
throughput look slightly better and drops look slightly rarer than they are —
so the figures above are a mild best case rather than a wrong answer. The
harness now waits for a line that only appears once every program is attached
and the ring buffer is built; re-running `scripts/bench.sh` produces numbers
without that skew.

---

# Alert budget

Throughput above answers "can it keep up". This answers the question an operator
actually decides on: **how many alerts per day, and what are they?** A tool that
catches everything and pages twice a day gets muted in week one, at which point
its detection quality stops mattering.

## Method

Nothing here can label ground truth, so the definition is operational: record a
host doing ordinary work, and every incident in that capture is a false positive
by construction. The capture is the assertion.

```bash
sudo kernelsentinel record --out normal-day.ndjson   # while the host does its usual work
kernelsentinel budget --capture normal-day.ndjson
```

`budget` replays the capture once per severity floor — reporting is stateful, so
the counts cannot be derived by filtering a single pass — and refuses to
extrapolate a daily rate from under an hour of recording.

## First measurement

Kali 7.0.12, 8 cores, 8 GB, single-user desktop. **2.3 hours** of ordinary
interactive work: shell, `apt`, `ssh`, editing, building.

| floor | incidents | per day |
|---|---:|---:|
| info | 13 | 138.5 |
| low | 13 | 138.5 |
| **medium** | **0** | **0.0** |
| high | 0 | 0.0 |
| critical | 0 | 0.0 |

219,066 events at 27 events/sec. **Zero alerts at the default `medium` floor**,
with no baseline applied.

That is the number the design is built around: the low-severity signals fired 13
times and none of them reached the alerting floor on their own, which is exactly
what scoring `privilege_escalation` and `credential_store_read` below the floor
is for. Whether they *chain* into something is the question those signals exist
to answer, and here nothing did.

## What fired below the floor

| count | signal | mostly |
|---:|---|---|
| 7 | `cross_uid_proc_read` | `/usr/bin/pidof` |
| 5 | `privilege_escalation` | `sudo`, `apt` |
| 2 | `ssh_private_key_read` | `/usr/bin/ssh` |

All three are behaving correctly and are worth naming:

- **`pidof` reads other users' `/proc` entries** as its whole job. Reading
  another user's `/proc/<pid>/cmdline` goes through `ptrace_may_access`, so the
  ptrace sensor sees it. Six of the seven cross-uid reads on this host were one
  utility doing what it exists to do.
- **`ssh` reads your private key** to authenticate with it. That is the same file
  access an exfiltration would perform, distinguishable only by what happens
  next — which is precisely why the signal scores 35 and cannot alert alone.
- **`privilege_escalation`** on `sudo` and `apt` is every ordinary escalation on
  the box.

Each is a baseline candidate rather than a detector bug. On a host where these
recur, `kernelsentinel baseline` learns them and `budget --baseline` shows what
that removed.

## What this does not establish

One desktop, one user, 2.3 hours. It says nothing yet about:

- a busy multi-user server, a CI runner, or a container host, where the event
  rate and the mix of routine behaviour are both different
- a full day: the extrapolation multiplies 2.3 hours of *interactive* use across
  24, which over-counts an idle night and under-counts a working day
- anything at fleet scale, which is the number that would actually settle it

If you run this, `budget --json` in a
[false-positive report](https://github.com/SysFr4m3r/kernelsentinel/issues/new?template=false_positive.yml)
is the single most useful thing this project can receive. It carries signal ids
and executable paths, no command lines.
