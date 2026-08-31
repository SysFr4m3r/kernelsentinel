#!/bin/bash
# Noise: a package manager installing a package that ships a SUID binary.
#   ks-expect: silence
#   ks-baseline: yes
#   ks-run: host
#
# docs/DETECTIONS.md lists this under suid_create's false positives: "package
# managers (dpkg, rpm) create SUID binaries on install ... These are the
# baseline's job." suid_create scores 45, so unlike most low signals it can
# reach an operator's alerting floor on its own once it chains, which makes it
# the documented false positive most likely to actually page someone.
#
# It uses a real dpkg install rather than a shell writing the file, and that
# distinction is the whole point. Baselining by executable means the pair
# learned is (suid_create, /usr/bin/dpkg) -- a package manager doing its job.
# Had the scenario used `cp` and `chmod` from the shell, the learned pair would
# be (suid_create, /bin/bash), which would also suppress an attacker's
# `chmod u+s` from any shell on the host. Same signal, same advice, and one of
# them blinds the detection it was meant to quieten.
#
# Everything it touches is named for this suite and removed afterwards.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root to install a package" >&2; exit 90; }
command -v dpkg-deb >/dev/null || { echo "dpkg-deb not present" >&2; exit 90; }
command -v dpkg >/dev/null || { echo "dpkg not present" >&2; exit 90; }

pkg=ks-noise-suid
work="$(mktemp -d)"
cleanup() { dpkg -r "$pkg" >/dev/null 2>&1 || true; rm -rf "$work"; }
trap cleanup EXIT

mkdir -p "$work/$pkg/DEBIAN" "$work/$pkg/usr/lib/ks-noise"
cat > "$work/$pkg/DEBIAN/control" <<EOF
Package: $pkg
Version: 1.0
Architecture: all
Maintainer: kernelsentinel noise suite <noreply@example.invalid>
Description: disposable package used to exercise the suid_create false positive
EOF

# The SUID payload a real package would ship: /bin/true, mode 4755. dpkg is what
# creates it on the target filesystem, which is the process the signal fires on.
cp /bin/true "$work/$pkg/usr/lib/ks-noise/helper" 2>/dev/null \
  || cp /usr/bin/true "$work/$pkg/usr/lib/ks-noise/helper"
chmod 4755 "$work/$pkg/usr/lib/ks-noise/helper"

dpkg-deb --build --root-owner-group "$work/$pkg" "$work/$pkg.deb" >/dev/null
dpkg -i "$work/$pkg.deb" >/dev/null

[[ -u /usr/lib/ks-noise/helper ]] || { echo "install did not set the SUID bit" >&2; exit 1; }

echo "[noise] package_install: dpkg installed a SUID binary"
echo "[noise] DOES exercise suid_create, attributed to dpkg rather than a shell"
