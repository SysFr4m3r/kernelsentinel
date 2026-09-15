#!/bin/bash
# Ordinary work: reading another process's /proc at the same privilege level.
#   ks-expect: silence
#   ks-forbid: cross_uid_proc_read
#
# This is the flood the ptrace sensor filters in-kernel: ps, top, pidof,
# systemd and container runtimes all read across /proc constantly, and every
# one of those reads goes through ptrace_access_check. Same-uid, read-only
# access is dropped before it reaches the ring buffer.
#
# docs/DETECTIONS.md records the cost of that filter -- a root attacker reading
# another root process's environ is not flagged -- and argues the trade is worth
# it. This pins the trade down as a property rather than a paragraph: if the
# filter is ever narrowed, the flood comes back and this scenario says so.
#
# The absence has to be checked at the info floor. cross_uid_proc_read scores
# 25, so at the medium floor its absence would prove nothing.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 90; }

sleep 20 &
target=$!
cleanup() { kill "$target" 2>/dev/null || true; }
trap cleanup EXIT
for _ in $(seq 1 20); do
	[[ -r "/proc/$target/environ" ]] && break
	sleep 0.1
done

# Same uid, read-only: environ, cmdline and maps, the three a credential
# harvester would reach for.
for f in environ cmdline maps; do
	cat "/proc/$target/$f" >/dev/null 2>&1 || true
done

echo "[noise] same_uid_proc_read: read environ, cmdline and maps of pid $target"
