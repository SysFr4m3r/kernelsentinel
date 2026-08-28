#!/usr/bin/env bash
# Run attack scenarios against a live agent and assert each one is detected.
#
#   sudo tests/attack/verify.sh                    # every scenario
#   sudo tests/attack/verify.sh suid_create        # one, by name
#   sudo KS_ENFORCE=on tests/attack/verify.sh      # with enforcement armed
#
# Two questions, one harness, chosen by each scenario's ks-expect header.
#
# FALSE NEGATIVES (tests/scenarios/, ks-expect: <signal>): did an attack that
# really happened produce the signal it should? Run at --min-severity info, so a
# correctly-suppressed low signal is not mistaken for a missing one.
#
# FALSE POSITIVES (tests/noise/, ks-expect: silence): does ordinary work stay
# quiet? Run at the *operational* floor instead, because the claim being tested
# is "this does not cry wolf in normal use", and alerting means MEDIUM and above.
# A tool that catches every attack and fires twice a day on dpkg gets muted in
# week one, at which point the detection quality stops mattering. The replay tests in tests/ cannot answer that --
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
NOISE="$REPO/tests/noise"
ENFORCE="${KS_ENFORCE:-off}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

[[ -x "$BIN" ]] || { echo "no binary at $BIN -- cargo build --release" >&2; exit 1; }

# A binary older than the code it is supposed to be testing produces the most
# expensive result this harness can give: a confident FAIL against a detection
# that was fixed, or a confident PASS over one that is broken. It happened --
# a scenario written for a new detection ran against yesterday's binary and
# reported the old behaviour as a missed detection.
#
# Refuse rather than rebuild: this runs under sudo, and `cargo build` here would
# leave a root-owned target/ behind.
newest="$(find "$REPO/src" "$REPO/bpf" "$REPO/Cargo.toml" -type f -newer "$BIN" -print -quit 2>/dev/null)"
if [[ -n "$newest" ]]; then
	cat >&2 <<-EOF
	$BIN is older than the source it tests.
	  first newer file: $newest

	Build it as your normal user, then re-run:
	  cargo build --release
	EOF
	exit 1
fi

[[ $EUID -eq 0 ]] || { echo "must run as root (the agent attaches BPF)" >&2; exit 1; }

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
	# A third question, alongside "was it detected" and "did anything fire".
	# `ks-forbid` names one signal that must NOT appear, and runs at info so
	# the absence is real rather than an artefact of the alerting floor.
	local forbid
	forbid="$(header "$script" ks-forbid)"
	if [[ -z "$expect" ]]; then
		printf '  %-32s SKIP  (no ks-expect header)\n' "$name"
		skip=$((skip + 1)); return
	fi

	local out="$WORK/$name.ndjson" log="$WORK/$name.log" slog="$WORK/$name.scenario"
	# The floor depends on the question being asked.
	#
	# Attack scenarios run at info: they ask "did the sensor fire", not "would
	# it have alerted". setcap (40) and ptrace_attach (30) sit below the default
	# MEDIUM floor and are correctly suppressed in normal operation, which an
	# earlier version of this harness misread as a missed detection.
	#
	# Noise scenarios run at the floor an operator actually alerts on, because
	# the claim under test is "ordinary work does not cry wolf" -- and crying
	# wolf means MEDIUM and above. Running these at info would report every
	# correctly-suppressed low signal as a false positive, which is exactly the
	# wrong answer.
	# Silence scenarios ask "does ordinary work cry wolf", and crying wolf means
	# MEDIUM and above -- at info every correctly-suppressed low signal would
	# read as a false positive.
	#
	# A forbid scenario asks the opposite question about one specific signal,
	# and must run at info: `credential_store_read` scores 30, so at the medium
	# floor its absence proves nothing. Suppression could be entirely broken and
	# a medium-floor run would still be silent.
	local floor=info
	[[ "$expect" == "silence" && -z "$forbid" ]] && floor=medium
	"$BIN" run --json --min-severity "$floor" --enforce "$ENFORCE" >"$out" 2>"$log" &
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
			>"$slog" 2>&1 || scenario_rc=$?
	else
		KS_COLD="${KS_COLD:-}" bash "$script" >"$slog" 2>&1 || scenario_rc=$?
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
		# The scenario's own output, not the agent's. Showing the tail of a
		# combined log printed the agent shutting down and hid the real error.
		sed 's/^/      /' "$slog" | tail -4
		fail=$((fail + 1)); FAILED+=("$name"); return
	fi

	if [[ -n "$forbid" ]]; then
		# Absence of one named signal. This is the only assertion that can
		# catch a *suppression* that has stopped working: the signal firing
		# here means the thing that was supposed to be recognised was not.
		if grep -q "\"$forbid\"" "$out"; then
			printf '  %-32s FIRED %s (must have been suppressed)\n' "$name" "$forbid"
			grep "\"$forbid\"" "$out" | head -2 | sed 's/^/      /' | cut -c1-160
			fail=$((fail + 1)); FAILED+=("$name")
		else
			printf '  %-32s PASS  no %s\n' "$name" "$forbid"
			grep -hE 'NOT exercised|DOES exercise|in use|re-run with' "$slog" 2>/dev/null \
				| sed 's/^\[noise\] /        note: /' || true
			pass=$((pass + 1))
		fi
		return
	fi

	if [[ "$expect" == "silence" ]]; then
		# Inverted: anything at MEDIUM or above during ordinary work is a false
		# positive, and naming it makes it actionable rather than "it is noisy".
		local fired
		fired="$(grep -o '"id":"[a-z_]*"' "$out" | sort | uniq -c \
			| sed 's/^ *//;s/"id"://g;s/"//g' | tr '\n' ' ')"
		if [[ -z "$fired" ]]; then
			printf '  %-32s PASS  silent\n' "$name"
			# Surface what the scenario says it actually exercised. A pass that
			# cannot tell you which path it took is the failure mode that has
			# already fooled this suite more than once: container_lifecycle went
			# green on a warm host without touching the code path that produced
			# the alerts it exists to catch.
			grep -hE 'NOT exercised|DOES exercise|in use|re-run with' "$slog" 2>/dev/null \
				| sed 's/^\[noise\] /        note: /' || true
			pass=$((pass + 1))
		else
			printf '  %-32s FALSE POSITIVE  %s\n' "$name" "$fired"
			# Name the offending processes. "5 runtime_socket_access" says
			# something is wrong; the subject and command line say what to fix,
			# and whether it belongs in a baseline or in the detector.
			python3 - "$out" <<'PYEOF' 2>/dev/null || true
import json, sys
seen = set()
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except ValueError:
        continue
    subj = d.get("subject", {})
    for sig in d.get("signals", []):
        key = (sig.get("id"), subj.get("comm"), sig.get("cmdline") or subj.get("cmdline", ""))
        if key in seen:
            continue
        seen.add(key)
        cmd = (key[2] or "")[:88]
        print(f"      {d.get('score','?'):>3}  {key[0]:<24} {key[1] or '?':<18} {cmd}")
        lin = " > ".join(d.get("lineage", [])[-4:])
        if lin:
            print(f"           {lin}")
PYEOF
			fail=$((fail + 1)); FAILED+=("$name")
		fi
		return
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

# A lab image older than its Dockerfile silently changes what the scenarios do:
# sensitive_write writes to /etc/cron.d, and an image predating that mkdir fails
# the write instead of testing the sensor. Rebuild rather than trust it.
if [[ $# -eq 0 ]] || grep -qls "ks-run: lab" "$SCENARIOS"/*.sh; then
	echo "rebuilding the lab image..."
	"$REPO/tests/lab/run.sh" build >/dev/null 2>&1 \
		|| echo "  warning: lab image build failed; lab scenarios may be stale" >&2
fi

echo "attack suite -- enforcement: $ENFORCE"
echo
if [[ $# -gt 0 ]]; then
	for n in "$@"; do
		if [[ -f "$SCENARIOS/$n.sh" ]]; then run_one "$SCENARIOS/$n.sh"
		elif [[ -f "$NOISE/$n.sh" ]]; then run_one "$NOISE/$n.sh"
		else echo "  no scenario named $n" >&2; fi
	done
else
	echo "attacks -- must be detected"
	for s in "$SCENARIOS"/*.sh; do run_one "$s"; done
	if compgen -G "$NOISE/*.sh" >/dev/null; then
		echo
		echo "ordinary work -- must stay quiet"
		for s in "$NOISE"/*.sh; do run_one "$s"; done
	fi
fi

echo
echo "  $pass passed, $fail failed, $skip skipped"
if [[ $fail -gt 0 ]]; then
	echo "  failed: ${FAILED[*]}"
	echo
	echo
	echo "  FAIL          an attack ran and the sensor did not report it."
	echo "  FALSE POSITIVE ordinary work produced an alert. Either the detection is"
	echo "                too eager, or it belongs in a baseline -- both are findings."
	echo "  FIRED         a signal that should have been suppressed was reported."
	echo "  ERROR         the scenario itself did not run; nothing was tested."
	exit 1
fi
