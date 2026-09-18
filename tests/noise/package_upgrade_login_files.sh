#!/bin/bash
# Noise: a package upgrade rewriting the login-time files added in v0.5.0.
#   ks-expect: silence
#   ks-run: host
#
# This session added /etc/pam.d, /etc/profile.d, /etc/ld.so.conf.d and friends
# to the watch list, scored 30-35. Package upgrades are the main legitimate
# writer of every one of them: any package shipping a PAM module, a profile
# script or a linker config rewrites its own file on upgrade, and dpkg does
# several in one run.
#
# The individual scores sit below the MEDIUM alerting floor on purpose. The
# question this asks is what happens when one process writes *several* of them:
# distinct signal kinds are what earn a chain bonus, and cred_config_write (35)
# plus persistence_write (30) in one lineage is arithmetically an incident well
# above the floor. If that is what happens, the detections added this session
# alert on `apt upgrade`, and the finding belongs here rather than in a user's
# inbox.
#
# Every file written is one this suite owns and removes. The real PAM stack,
# the real profile scripts and the real linker config are never touched, so a
# failed run cannot affect authentication or library loading.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to write /etc" >&2; exit 90; }

targets=(
	/etc/pam.d/ks-noise-probe
	/etc/profile.d/ks-noise-probe.sh
	/etc/ld.so.conf.d/ks-noise-probe.conf
)
cleanup() { rm -f "${targets[@]}"; }
trap cleanup EXIT
cleanup

# One process writing several of them, which is the shape that chains.
for t in "${targets[@]}"; do
	d="$(dirname "$t")"
	[[ -d "$d" ]] || continue
	printf '%s\n' '# kernelsentinel noise scenario, not a real policy' > "$t"
	chmod 644 "$t"
done

echo "[noise] package_upgrade_login_files: rewrote ${#targets[@]} login-time files"
