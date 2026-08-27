#!/usr/bin/env bash
# Run attack scenarios against a live agent and assert each one is detected.
#
#   sudo tests/attack/verify.sh                    # every scenario
#   sudo tests/attack/verify.sh suid_create        # one, by name
#   sudo KS_ENFORCE=on tests/attack/verify.sh      # with enforcement armed
#
# This tests FALSE NEGATIVES: does an attack that really happened actually
# produce the signal it should? It runs the agent at --min-severity info so a
# correctly-suppressed low signal is not mistaken for a missing one. The replay tests in tests/ cannot answer that --
# they feed the detector events I constructed, which is how a container escape
# detection shipped, passed 113 tests, and failed against the real attack. The
# scenario runs the attack for real and the assertion reads the agent's own
# NDJSON output.
#
# Needs root: the agent attaches BPF. Some scenarios need docker.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${KS_BIN:-$REPO/target/release/kernelsentinel}"
SCENARIOS="$REPO/tests/scenarios"
ENFORCE="${KS_ENFORCE:-off}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

[[ $EUID -eq 0 ]] || { echo "must run as root (the agent attaches BPF)" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "no binary at $BIN -- cargo build --release" >&2; exit 1; }

# `ks-expect:` names the signal the scenario must produce; `ks-run:` says whether
# it executes on the host or inside the lab container.
header() { sed -n "s/^# *$2: *//p" "$1" | head -1; }

pass=0 fail=0 skip=0
declare -a FAILED=()

run_one() {
	local script="$1" name expect where caps
	name="$(basename "$script" .sh)"
	expect="$(header "$script" ks-expect)"
	where="$(header "$script" ks-run)"
	# An attack that needs a capability must say so. Silently running it
	# without one produces a scenario that fails and looks like a missed
	# detection -- which is exactly what happened to setcap.
	caps="$(header "$script" ks-caps)"
	if [[ -z "$expect" ]]; then
		printf '  %-32s SKIP  (no ks-expect header)\n' "$name"
		skip=$((skip + 1)); return
	fi

	local out="$WORK/$name.ndjson" log="$WORK/$name.log"
	# --min-severity info on purpose. This suite asks "did the sensor fire",
	# not "would it have alerted": setcap (40) and ptrace_attach (30) score
	# below the default MEDIUM floor and are correctly suppressed in normal
	# operation, which the first version of this harness misread as a missed
	# detection. Alerting thresholds are covered by the replay tests.
	"$BIN" run --json --min-severity info --enforce "$ENFORCE" >"$out" 2>"$log" &
	local agent=$!

	# Wait for the sensors, rather than sleeping and hoping. A scenario that
	# runs before the hooks attach would look exactly like a missed detection.
	local waited=0
	until grep -q "sensors attached" "$log" 2>/dev/null; do
		sleep 0.2; waited=$((waited + 1))
		if ! kill -0 $agent 2>/dev/null || [[ $waited -gt 100 ]]; then
			printf '  %-32s ERROR (agent did not attach)\n' "$name"
			sed 's/^/      /' "$log" | tail -5
			fail=$((fail + 1)); FAILED+=("$name"); return
		fi
	done

	local scenario_rc=0
	if [[ "$where" == "lab" ]]; then
		KS_CAPS="$caps" "$REPO/tests/lab/run.sh" run "bash /scenarios/$name.sh" \
			>>"$log" 2>&1 || scenario_rc=$?
	else
		bash "$script" >>"$log" 2>&1 || scenario_rc=$?
	fi

	sleep 1              # let the last events drain through the ring buffer
	kill -INT $agent 2>/dev/null; wait $agent 2>/dev/null

	if [[ $scenario_rc -eq 90 ]]; then
		printf '  %-32s SKIP  (prerequisite missing)\n' "$name"
		skip=$((skip + 1)); return
	fi
	if [[ $scenario_rc -ne 0 ]]; then
		# Critical distinction: the attack never happened, so the sensor had
		# nothing to miss. Reporting this as a failed detection would send
		# someone hunting a bug in the detector that does not exist.
		printf '  %-32s ERROR (scenario failed rc=%s -- the attack did not run)\n' \
			"$name" "$scenario_rc"
		sed 's/^/      /' "$log" | tail -4
		fail=$((fail + 1)); FAILED+=("$name"); return
	fi

	# The assertion: the agent's own output must name the expected signal.
	if grep -q "\"$expect\"" "$out"; then
		# From the matching incident specifically. Grepping the first score in
		# the file reports some unrelated low-severity incident's number, which
		# made every scenario look like it scored 25.
		local score
		score="$(grep "\"$expect\"" "$out" | head -1 \
			| grep -o '"score":[0-9]*' | head -1 | cut -d: -f2)"
		printf '  %-32s PASS  %s (score %s)\n' "$name" "$expect" "${score:-?}"
		pass=$((pass + 1))
	else
		printf '  %-32s FAIL  expected %s, got: %s\n' "$name" "$expect" \
			"$(grep -o '"id":"[a-z_]*"' "$out" | sort -u | tr '\n' ' ' | head -c 120)"
		fail=$((fail + 1)); FAILED+=("$name")
	fi
}

echo "attack suite -- enforcement: $ENFORCE"
echo
if [[ $# -gt 0 ]]; then
	for n in "$@"; do run_one "$SCENARIOS/$n.sh"; done
else
	for s in "$SCENARIOS"/*.sh; do run_one "$s"; done
fi

echo
echo "  $pass passed, $fail failed, $skip skipped"
if [[ $fail -gt 0 ]]; then
	echo "  failed: ${FAILED[*]}"
	echo
	echo "  A failure here means an attack really happened and the sensor did not"
	echo "  report it. That is the failure mode replay tests cannot detect."
	exit 1
fi
