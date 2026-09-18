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
# So this scenario runs in two passes: a recorded learning pass where the harness
# repeats it, and one verify pass with the resulting baseline applied. The
# assertion is on the verify pass.
#
# The repetition is not padding. A pair seen once keeps ~85% of its score, by
# design, so an attacker present during a "clean" recording cannot whitelist
# themselves with a single action. "Baseline them" claims that *routine*
# behaviour stops alerting, and routine means recurring -- so a learning pass
# that runs the activity once tests something the documentation never claimed.
#
# The first version of this test did exactly that and failed, which is how the
# gap in docs/DETECTIONS.md was found: the advice was given in seven places
# without ever saying the activity has to recur in the capture.
#
# The shadow read is not padding either, and it is newer than the rest. Until
# v0.5.0 the two writes alerted on their own: cron.d and sudoers.d emit
# persistence_write and cred_config_write, two ids, and the chain bonus turned
# them into an 82. Scoring now groups ids by behaviour, so two writes are one
# behaviour seen twice and this activity correctly stays below the floor -- at
# which point this scenario had nothing left to baseline and the harness said so
# ("nothing alerted without the baseline either").
#
# Reading the shadow file is a second *behaviour*, not a second write, so the
# activity alerts again and the baseline has something real to suppress. That is
# what this scenario exists to test, and it now tests it across two families
# rather than one, which is strictly the harder case.
#
# It writes only into files it creates and removes, both named for this suite,
# and reads /etc/shadow without copying, printing or storing any of it.
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

# An administrator inspecting password aging. Reads the shadow file and keeps
# nothing: a second behaviour, so the activity above is scored as more than one
# kind of evidence.
cat /etc/shadow > /dev/null

echo "[noise] admin_config_change: wrote cron.d and sudoers.d, read shadow, as root"
echo "[noise] DOES exercise persistence_write, cred_config_write and credential_store_read"
