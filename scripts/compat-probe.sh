#!/usr/bin/env bash
# Load the sensors on whatever kernel this is, and report what attached.
#
# This is the check CI never had. Until now the pipeline compiled the BPF object
# and ran unprivileged replay tests -- every claim about the object *attaching*
# came from one developer machine, which happens to attach 11 of 11 and can
# therefore never exercise the path where some do not.
#
# What it asserts is deliberately narrow, because most of what varies between
# kernels is allowed to vary:
#
#   - the agent starts at all, and the object loads
#   - `exec` attaches, the one sensor with no fallback
#   - the run is clean enough to report a count
#
# It must NOT assert 11 of 11. A kernel without BPF-LSM losing six sensors is
# documented, supported behaviour, and a CI job that demanded the full set would
# fail correctly-degrading kernels and pass only on machines like the author's.
#
# The count and the missing sensors go to stdout as one machine-readable line,
# for docs/COMPATIBILITY.md to be checked against rather than guessed at.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${KS_BIN:-$REPO/target/debug/kernelsentinel}"
SECS="${KS_PROBE_SECS:-8}"

[[ -x "$BIN" ]] || { echo "no binary at $BIN" >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo "must run as root (attaching BPF)" >&2; exit 1; }

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

echo "--- doctor ---"
# doctor exits non-zero when a check is fatal; that is information, not a
# failure of this probe, so its status is reported rather than propagated.
"$BIN" doctor; echo "doctor exit: $?"

echo
echo "--- attach ---"

# Run the agent, wait for it to be genuinely ready, then provoke each family of
# sensor and see which ones answer.
#
# Counting attachments is not enough, and the Ubuntu runner is why. The kernel
# accepts an lsm/ program whether or not "bpf" is in the active LSM list -- the
# attach succeeds either way, and only the hook being *invoked* depends on it.
# So an agent can report eleven of eleven on a kernel where six of them will
# never see an event. "Attached" is a claim about a syscall's return value;
# "live" is a claim about the sensor doing its job, and only the second one is
# worth putting in a compatibility table.
out="$(mktemp)"
work="$(mktemp -d /tmp/ks-probe.XXXXXX)"
trap 'rm -rf "$log" "$out" "$work"' EXIT

"$BIN" run --json --min-severity info >"$out" 2>"$log" &
agent=$!

waited=0
until grep -q "ready, streaming events" "$log" 2>/dev/null; do
	sleep 0.2
	waited=$((waited + 1))
	if ! kill -0 $agent 2>/dev/null || [[ $waited -gt $((SECS * 5)) ]]; then
		echo "the agent never became ready:" >&2
		sed 's/^/  /' "$log" >&2
		exit 1
	fi
done

# One provocation per sensor family, each chosen because a specific signal
# should follow it and nothing else produces that signal.
cp /bin/true "$work/ks-probe" 2>/dev/null || cp /usr/bin/true "$work/ks-probe"
"$work/ks-probe" || true              # tracepoint exec -> exec_from_tmp
chmod u+s "$work/ks-probe" || true    # lsm/path_chmod  -> suid_create
cat /etc/shadow >/dev/null 2>&1 || true  # lsm/file_open -> credential_store_read

sleep 1                               # let the ring buffer drain
kill -INT $agent 2>/dev/null
wait $agent 2>/dev/null
sed 's/^/  /' "$log"

live=""
for pair in "exec:exec_from_tmp" "path_chmod:suid_create" "file_open:credential_store_read"; do
	sensor="${pair%%:*}"; signal="${pair##*:}"
	if grep -q "\"$signal\"" "$out"; then
		live="${live:+$live,}$sensor"
	fi
done

if ! grep -q "ready, streaming events" "$log"; then
	echo "the agent never reached its ready line -- it did not finish starting" >&2
	exit 1
fi
attached="$(grep -oE '[0-9]+ of [0-9]+ sensors active' "$log" | head -1)"
if [[ -z "$attached" ]]; then
	echo "the agent never reported a sensor count -- it did not get that far" >&2
	exit 1
fi
have="${attached%% of *}"
want="$(echo "$attached" | sed -E 's/.* of ([0-9]+) .*/\1/')"

# exec has no fallback: sensors.rs bails without it, so reaching the count line
# already proves it attached. Assert it anyway -- the day that bail is loosened,
# this is the check that should notice.
if grep -q 'unavailable: exec ' "$log"; then
	echo "the exec sensor did not attach; there is no process graph without it" >&2
	exit 1
fi

missing="$(grep -oE 'unavailable: [a-z_]+' "$log" | sed 's/unavailable: //' | paste -sd, -)"
lsm=inactive
grep -qw bpf /sys/kernel/security/lsm 2>/dev/null && lsm=active

# The distribution identifier is what lets a result line be matched back to a
# row in docs/COMPATIBILITY.md. Without it a recorded result cannot retire the
# claim it was produced to check.
distro=unknown
if [[ -r /etc/os-release ]]; then
	# shellcheck disable=SC1091
	. /etc/os-release
	distro="${ID:-unknown}-${VERSION_ID:-rolling}"
fi

echo
printf 'ks-compat: distro=%s kernel=%s arch=%s bpflsm=%s sensors=%s/%s missing=%s live=%s\n' \
	"$distro" "$(uname -r)" "$(uname -m)" "$lsm" "$have" "$want" "${missing:-none}" "${live:-none}"

# The exec sensor is the one with no fallback, and the only one this can insist
# on: without it there is no process graph. The lsm/ ones are allowed to be
# absent -- that is what the compatibility table is for -- but they are not
# allowed to be counted as attached while silently seeing nothing, so the result
# line records what answered rather than what loaded.
if [[ ",$live," != *",exec,"* ]]; then
	echo "the exec sensor attached but produced no event for a real exec" >&2
	exit 1
fi
