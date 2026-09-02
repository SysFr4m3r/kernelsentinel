#!/bin/bash
# Scenario: a SUID root binary moved into place, never created there.
#   MITRE ATT&CK: T1548.001 (Setuid and Setgid)
#   ks-expect: suid_create
#   ks-run: host
#
# The third route to the same artifact, and the one this project has claimed is
# an evasion without ever running it.
#
#   suid_create_preserved.sh   cp -p        -> caught by path_chmod (cp fchmods)
#   suid_create_direct.sh      open(O_CREAT)-> caught by path_mknod
#   this one                   rename(2)    -> claimed to pass through neither
#
# A rename is not a create and not a chmod, so on the face of it nothing fires.
# But the file has to exist somewhere first, and creating it there goes through
# the same hooks -- so the interesting question is not whether the rename is
# seen, it is whether the *original* creation was, and whether what the operator
# ends up looking at points anywhere useful.
#
# Staged under a directory an attacker would plausibly use, then moved to its
# final name in one syscall.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to hold a SUID root mode" >&2; exit 90; }

stage=/tmp/.ks-stage-$$
target=/tmp/.ks-suid-renamed
cleanup() { rm -f "$stage" "$target"; }
trap cleanup EXIT
rm -f "$stage" "$target"

# Same filesystem, so this is a rename(2) and not a copy.
cp -p /usr/bin/su "$stage"
mv "$stage" "$target"

[[ -u "$target" ]] || { echo "setup failed: $target is not SUID" >&2; exit 1; }
echo "[scenario] suid_create_renamed: $(stat -c '%U %a' "$target") arrived by rename(2)"
