#!/bin/bash
# Scenario: armed enforcement must not block the host itself.
#   MITRE ATT&CK: T1611 (Escape to Host)
#   ks-expect: kernel_escape_hatch_write
#   ks-run: host
#
# Enforcement is the only feature here that can make a syscall fail, and the
# rule that keeps it from breaking a host is one comparison in deny_decision():
# a task whose mount namespace equals the host's is never denied. Five separate
# paths fail open -- no config, mode off, no recorded host namespace, no
# mnt_namespace type in BTF, unreadable namespace -- and none of them had ever
# been exercised on hardware with enforcement actually armed.
#
# Getting this wrong does not cost a detection. It denies root's own writes to
# core_pattern, modprobe and poweroff_cmd on every host running the agent.
#
# Nothing on the system changes. The scenario reads core_pattern and writes the
# identical bytes back: the open-for-write is what reaches the LSM hook, and the
# value is its own replacement, so an interrupted run leaves the host exactly as
# it found it. Contrast container_escape_corepattern.sh, which must write a
# different value and therefore has to restore it.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to write core_pattern" >&2; exit 90; }

# Only meaningful with enforcement armed. Without it every write succeeds and
# the assertion below proves nothing.
if [[ "${KS_ENFORCE:-off}" != "on" ]]; then
	echo "needs KS_ENFORCE=on; nothing to prove with enforcement off" >&2
	exit 90
fi

hatch=/proc/sys/kernel/core_pattern
before="$(cat "$hatch")"

# The write the host is entitled to make. If enforcement denies this, the agent
# is breaking the machine it is supposed to be watching.
if ! printf '%s\n' "$before" > "$hatch" 2>/dev/null; then
	echo "DENIED: enforcement blocked a host write to $hatch" >&2
	echo "this is the failure mode that breaks production hosts" >&2
	exit 1
fi

after="$(cat "$hatch")"
[[ "$after" == "$before" ]] || {
	echo "core_pattern changed ($before -> $after); the scenario must be inert" >&2
	exit 1
}

echo "[scenario] enforce_never_blocks_the_host: host write to $hatch allowed, value unchanged"
