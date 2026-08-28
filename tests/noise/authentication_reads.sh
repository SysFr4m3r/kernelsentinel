#!/bin/bash
# Noise: the credential store being read by the programs whose job that is.
#   ks-expect: silence
#   ks-forbid: credential_store_read
#   ks-run: host
#
# This is the only scenario that can catch the credential-read suppression
# having quietly stopped working, and it exists because nothing else could.
#
# Suppression turns on the reader's file identity: the exec event carries the
# inode of mm->exe_file, userspace matches it against the host's real
# authentication binaries, and a match means the read is not reported. If any
# link in that chain breaks -- the BPF read returns zero, the device encoding is
# wrong, the table resolves nothing -- then *every* authentication on the host
# starts producing credential_store_read.
#
# The attack scenarios cannot see that: credential_read_name_spoof asserts the
# signal fires for an impostor, which it also would if identity were dead for
# everyone. The other noise scenarios cannot see it either: they run at the
# MEDIUM floor and credential_store_read scores 30, so a flood of them is
# invisible there. Hence ks-forbid, which runs at info and names the one signal
# that must not appear.
#
# `passwd -S` reads /etc/shadow through the real /usr/bin/passwd and changes
# nothing -- it prints password status and aging fields.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 90; }
command -v passwd >/dev/null || { echo "no passwd(1)" >&2; exit 90; }

if ! passwd -S root >/dev/null 2>&1; then
	echo "passwd -S did not run; nothing was exercised" >&2
	exit 90
fi
echo "[noise] authentication_reads: /usr/bin/passwd read the shadow file"
echo "[noise] DOES exercise the identity-based suppression path"
