#!/bin/bash
# Noise: an administrator doing ordinary configuration work.
#   ks-expect: silence
#   ks-baseline: yes
#   ks-run: host
#
# Writing /etc/cron.d and /etc/sudoers.d as root is structurally identical to
# the persistence an attacker establishes -- that is why persistence_write and
# cred_config_write exist, and why they fire here. docs/DETECTIONS.md answers
# this in seven separate places with "baseline them".
#
# That advice had never been tested. The baseline was verified against fixtures
# built by hand and against a nine-second capture; no test had ever learned from
# real activity and checked the same activity then stayed quiet. Advice repeated
# seven times in the documentation of a security tool should not rest on that.
#
# So this scenario runs twice: once recorded, to learn from, and once with the
# resulting baseline applied. The assertion is on the second run.
#
# It writes only into files it creates and removes, both named for this suite.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to write /etc" >&2; exit 90; }

cron=/etc/cron.d/ks-noise-admin
sudoers=/etc/sudoers.d/ks-noise-admin
cleanup() { rm -f "$cron" "$sudoers"; }
trap cleanup EXIT

mkdir -p /etc/cron.d /etc/sudoers.d

# A scheduled job, the way configuration management writes one.
printf '# managed by the kernelsentinel noise suite\n0 4 * * * root /bin/true\n' > "$cron"
chmod 644 "$cron"

# A sudoers drop-in. visudo -c validates without installing anything.
printf 'ks-noise ALL=(ALL) NOPASSWD: /bin/true\n' > "$sudoers"
chmod 440 "$sudoers"
command -v visudo >/dev/null && visudo -c -f "$sudoers" >/dev/null 2>&1 || true

echo "[noise] admin_config_change: wrote cron.d and sudoers.d as root"
echo "[noise] DOES exercise persistence_write and cred_config_write"
