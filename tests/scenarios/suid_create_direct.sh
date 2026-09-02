#!/bin/bash
# Scenario: a SUID root binary created by open(2), never touched by chmod.
#   MITRE ATT&CK: T1548.001 (Setuid and Setgid)
#   ks-expect: suid_create
#   ks-run: host
#
# The second half of the evasion docs/DETECTIONS.md records. Where
# suid_create_preserved.sh uses `cp -p` -- which may or may not reach chmod
# internally, that is the point of running it -- this one leaves no doubt: the
# mode is passed to open(2) at creation, and the file is never chmod'd at all.
#
# `security_path_chmod` cannot see this by construction. If suid_create still
# fires, something else is catching it and the documented evasion is narrower
# than stated. If it does not, an attacker who can write a file can leave a
# setuid-root binary on the host without tripping the detection that exists for
# exactly that artifact.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to create a SUID root file" >&2; exit 90; }
command -v python3 >/dev/null || { echo "python3 not present" >&2; exit 90; }

target=/tmp/.ks-suid-direct
cleanup() { rm -f "$target"; }
trap cleanup EXIT
rm -f "$target"

python3 - "$target" <<'PY'
import os, shutil, stat, sys
target = sys.argv[1]
os.umask(0)                      # umask would otherwise clear the mode bits
fd = os.open(target, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o4755)
with os.fdopen(fd, "wb") as out, open("/usr/bin/su", "rb") as src:
    shutil.copyfileobj(src, out)
mode = stat.S_IMODE(os.stat(target).st_mode)
if not mode & stat.S_ISUID:
    sys.exit(f"setup failed: mode is {mode:04o}, not SUID")
PY

[[ -u "$target" ]] || { echo "setup failed: $target is not SUID" >&2; exit 1; }
echo "[scenario] suid_create_direct: $(stat -c '%U %a' "$target") via open(2), no chmod anywhere"
