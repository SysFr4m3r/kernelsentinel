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
