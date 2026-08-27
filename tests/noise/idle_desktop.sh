#!/bin/bash
# Noise: the machine doing nothing in particular.
#   ks-expect: silence
#   ks-run: host
#
# The baseline case, and not a trivial one here: a 40-second capture on this
# desktop produced 230 exec events, 79% of them from one panel applet polling
# for a VPN address once a second. If ambient desktop churn alerts, nothing
# else matters.
set -euo pipefail
sleep 20
echo "[noise] idle_desktop complete"
