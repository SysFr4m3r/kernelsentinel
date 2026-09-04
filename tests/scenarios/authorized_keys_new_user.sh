#!/bin/bash
# Scenario: SSH persistence in the home directory of a user created after the
# agent started.
#   MITRE ATT&CK: T1098.004 (SSH Authorized Keys)
#   ks-expect: authorized_keys_write
#   ks-run: host
#
# The watch list enumerates `/home/*/.ssh/` once, at startup, because
# authorized_keys lives at a per-user path no single prefix covers.
# docs/DETECTIONS.md records the consequence as an evasion: "Per-user
# authorized_keys is covered only for existing /home/* and /root at startup."
#
# That is a claim about a long-running daemon, which is how this actually runs.
# An attacker with root does not need to find an existing account to backdoor --
# creating one is a normal administrative action that happens to arrive with a
# home directory nothing is watching.
#
# The daemon re-enumerates /home on a short cadence and adds what is new, so the
# window is bounded rather than permanent. This waits for one of those passes
# before writing the key -- which is also the honest reproduction: an attacker
# creating an account and immediately backdooring it inside that window is
# genuinely not caught, and the fix bounds the exposure rather than removing it.
#
# The account is created and removed inside this script, and the name is checked
# first so a real account can never be the one deleted.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to create a user" >&2; exit 90; }
command -v useradd >/dev/null || { echo "useradd not present" >&2; exit 90; }

u=ks-evasion-probe
if id "$u" >/dev/null 2>&1; then
	echo "refusing to run: user $u already exists and this would delete it" >&2
	exit 90
fi

cleanup() { userdel -r "$u" >/dev/null 2>&1 || true; }
trap cleanup EXIT

useradd -m "$u" >/dev/null
home="$(getent passwd "$u" | cut -d: -f6)"
[[ -d "$home" ]] || { echo "setup failed: no home for $u" >&2; exit 1; }

# One refresh interval plus slack. See WATCH_REFRESH in src/sensors.rs.
sleep 17

mkdir -p "$home/.ssh"
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI+kernelsentinel-noise attacker@example.invalid' \
	> "$home/.ssh/authorized_keys"
chmod 600 "$home/.ssh/authorized_keys"

echo "[scenario] authorized_keys_new_user: wrote $home/.ssh/authorized_keys"
echo "[scenario] that home directory did not exist when the agent built its watch list"
