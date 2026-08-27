#!/bin/bash
# Scenario: an unprivileged process gaining euid 0 through a SUID binary.
#   MITRE ATT&CK: T1068 (Exploitation for Privilege Escalation)
#   ks-expect: privilege_escalation
#   ks-run: host
#
# Host, not lab: the lab runs with --security-opt no-new-privileges, which
# blocks SUID escalation by design. That hardening is correct and worth keeping,
# so this transition simply cannot be produced in there.
#
# Uses an existing SUID binary rather than creating one. A SUID-root binary on
# the host, even briefly, is a real privilege-escalation primitive, and a test
# that leaves one lying around is worse than the bug it looks for. `--help`
# makes the binary do nothing; the transition happens at exec, which is the
# point -- commit_creds sees it without setuid(2) ever being called.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must start as root to drop privilege" >&2; exit 90; }
command -v setpriv >/dev/null || { echo "setpriv required (util-linux)" >&2; exit 90; }

suid=""
for c in /usr/bin/passwd /usr/bin/chsh /usr/bin/gpasswd; do
	[[ -u "$c" ]] && { suid="$c"; break; }
done
[[ -n "$suid" ]] || { echo "no SUID binary available to exec" >&2; exit 90; }

echo "[scenario] exec'ing $suid as uid 1000"
setpriv --reuid=1000 --regid=1000 --clear-groups "$suid" --help >/dev/null 2>&1 || true
echo "[scenario] privilege_escalation complete"
