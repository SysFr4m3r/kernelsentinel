#!/usr/bin/env bash
# Measure what the agent costs and where it starts losing events.
#
#   sudo scripts/bench.sh                 # idle, moderate and saturation runs
#   sudo scripts/bench.sh --duration 60   # longer samples
#
# Reports events/sec, drop rate, CPU and peak RSS. The event and drop counts
# come from the agent's own counters -- the same numbers it ships in every
# heartbeat -- rather than from anything this script infers, so a discrepancy
# here is a discrepancy in what the tool reports about itself.
#
# A drop is a missed detection, so the number that matters most is not the peak
# throughput but the rate at which drops begin.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${KS_BIN:-$REPO/target/release/kernelsentinel}"
DURATION="${DURATION:-20}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; jobs -p | xargs -r kill 2>/dev/null' EXIT

while [[ $# -gt 0 ]]; do
	case "$1" in
	--duration) DURATION="$2"; shift 2 ;;
	*) echo "unknown option: $1" >&2; exit 2 ;;
	esac
done

[[ $EUID -eq 0 ]] || { echo "must run as root (the agent attaches BPF)" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "no binary at $BIN -- cargo build --release" >&2; exit 1; }

ticks="$(getconf CLK_TCK)"

# Spawn processes as fast as a shell can, or paced. Each exec produces a fork,
# an exec and an exit event, so the event rate is roughly three times this.
workload() { # workload <mode>
	case "$1" in
	idle) sleep "$DURATION" ;;
	moderate)
		local end=$((SECONDS + DURATION))
		while ((SECONDS < end)); do /bin/true; sleep 0.01; done ;;
	saturate)
		# Every core, unpaced. The point is to find the ceiling, not to be fair.
		spawners "$(nproc)" ;;
	# w1..w8 ramp between "no drops" and "saturated". The first run of this
	# benchmark jumped from 280 events/sec with zero drops straight to 11,400
	# with 41% dropped, which located the ceiling somewhere inside a 40x range
	# -- and the onset rate is the number the doc says matters most.
	w1) spawners 1 ;;
	w2) spawners 2 ;;
	w4) spawners 4 ;;
	esac
}

# N unpaced spawn loops. Parallel workers rather than a paced sleep because
# bash cannot pace finely enough to be meaningful at these rates -- sleep 0.001
# costs more than the work it separates.
spawners() {
	local end=$((SECONDS + DURATION)) n
	for ((n = 0; n < $1; n++)); do
		( while ((SECONDS < end)); do /bin/true; done ) &
	done
	wait
}

run() { # run <mode>
	local mode="$1" out="$WORK/$mode.log"
	"$BIN" run --json --min-severity critical >/dev/null 2>"$out" &
	local pid=$!

	local waited=0
	until grep -q "sensors attached" "$out" 2>/dev/null; do
		sleep 0.2; waited=$((waited + 1))
		if ! kill -0 $pid 2>/dev/null || ((waited > 100)); then
			echo "  $mode: agent failed to attach" >&2; return 1
		fi
	done

	# CPU is measured from the delta, not the total: the /proc bootstrap at
	# startup is real work but not steady-state, and including it would flatter
	# or penalise the number depending on how long the run lasted.
	local c0 c1 peak=0 rss
	c0=$(awk '{print $14+$15}' "/proc/$pid/stat" 2>/dev/null || echo 0)
	local t0=$SECONDS

	workload "$mode" &
	local wl=$!
	while kill -0 $wl 2>/dev/null; do
		rss=$(awk '/VmRSS/{print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
		((rss > peak)) && peak=$rss
		sleep 0.5
	done
	wait $wl 2>/dev/null

	c1=$(awk '{print $14+$15}' "/proc/$pid/stat" 2>/dev/null || echo 0)
	local elapsed=$((SECONDS - t0))
	((elapsed == 0)) && elapsed=1

	kill -INT $pid 2>/dev/null; wait $pid 2>/dev/null

	# The agent's own counters, printed on shutdown.
	local line events drops
	line=$(grep -o '[0-9]* events emitted, [0-9]* ring buffer drops' "$out" | tail -1)
	events=$(echo "$line" | awk '{print $1}'); events=${events:-0}
	drops=$(echo "$line" | awk '{print $4}'); drops=${drops:-0}

	awk -v m="$mode" -v e="$events" -v d="$drops" -v s="$elapsed" \
	    -v c0="$c0" -v c1="$c1" -v tk="$ticks" -v r="$peak" 'BEGIN {
		eps = e / s
		cpu = (c1 - c0) / tk / s * 100
		pct = (e + d) > 0 ? d * 100 / (e + d) : 0
		printf "  %-10s %10.0f %12.1f %9d %8.2f%% %8.1f%% %8.1f\n", m, e, eps, d, pct, cpu, r/1024
	}'
}

printf "kernelsentinel benchmark -- %ss per mode, %s cores, kernel %s\n\n" \
	"$DURATION" "$(nproc)" "$(uname -r)"
printf "  %-10s %10s %12s %9s %9s %9s %8s\n" \
	mode events events/sec drops "drop%" "cpu%" "rss MB"
printf "  %-10s %10s %12s %9s %9s %9s %8s\n" \
	"----------" "----------" "------------" "---------" "---------" "---------" "--------"
for mode in idle moderate w1 w2 w4 saturate; do run "$mode"; done
echo
echo "  Drops are missed detections. The number worth quoting is not the peak"
echo "  rate but the one where drop% stops being zero -- above it, coverage is"
echo "  no longer complete, and the panel marks such a host accordingly."
