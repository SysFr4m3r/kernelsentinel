#!/usr/bin/env bash
# Generate bpf/vmlinux.h from this machine's BTF.
#
# Shared by ci.yml and release.yml so the two cannot drift -- they already did
# once, and the copy that drifted was the one that broke.
#
# Why this is not just "run bpftool": the tool has to be new enough to parse the
# running kernel's BTF, and on a CI runner it often is not. GitHub's images pair
# a 6.x kernel with whatever linux-tools-generic supplies, which has been as old
# as 5.15 -- and a 5.15 parser cannot read BTF_KIND_ENUM64 (kernel 6.0+), so it
# fails with EINVAL. /usr/sbin/bpftool is worse: a wrapper pinned to the exact
# running kernel, whose linux-tools package is not in apt for Azure kernels.
#
# So: try each candidate, keep the first that actually produces output, and fall
# back to a pinned upstream build. Testing the output rather than the version
# means a broken wrapper is skipped for the same reason an old binary is.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$REPO/bpf/vmlinux.h"
BTF=/sys/kernel/btf/vmlinux

# Pinned rather than "latest": a build input that can change under you is not a
# reproducible build. Update both together.
PIN_VERSION="v7.5.0"
PIN_SHA256="6b81db78c797e63f13e644ceb2064e5236afaf904bbaaa367785170819768f0a"

[ -r "$BTF" ] || { echo "no readable BTF at $BTF -- kernel lacks CONFIG_DEBUG_INFO_BTF" >&2; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

emit() { # emit <bpftool-path> -> 0 if it produced a usable header
	[ -x "$1" ] || return 1
	"$1" btf dump file "$BTF" format c > "$tmp" 2>/dev/null || return 1
	# A truncated or empty dump is a failure that exits 0 on some versions.
	[ -s "$tmp" ] && grep -q '__VMLINUX_H__' "$tmp"
}

for candidate in /usr/lib/linux-tools/*/bpftool "$(command -v bpftool 2>/dev/null || true)"; do
	if emit "$candidate"; then
		mkdir -p "$(dirname "$OUT")"
		mv "$tmp" "$OUT"
		echo "vmlinux.h: $(wc -l < "$OUT") lines, via $candidate"
		exit 0
	fi
	[ -n "$candidate" ] && [ -x "$candidate" ] && echo "note: $candidate cannot parse this kernel's BTF, trying the next" >&2
done

echo "no usable system bpftool; fetching pinned upstream $PIN_VERSION" >&2
arch="$(uname -m)"; case "$arch" in x86_64) arch=amd64 ;; aarch64) arch=arm64 ;; esac
url="https://github.com/libbpf/bpftool/releases/download/$PIN_VERSION/bpftool-$PIN_VERSION-$arch.tar.gz"
dl="$(mktemp -d)"; trap 'rm -f "$tmp"; rm -rf "$dl"' EXIT
curl -fsSL -o "$dl/bpftool.tar.gz" "$url"
echo "$PIN_SHA256  $dl/bpftool.tar.gz" | sha256sum -c - >/dev/null \
	|| { echo "checksum mismatch for $url -- refusing to use it" >&2; exit 1; }
tar -xzf "$dl/bpftool.tar.gz" -C "$dl"
chmod +x "$dl/bpftool"

emit "$dl/bpftool" || { echo "pinned bpftool $PIN_VERSION also failed to dump BTF" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"
mv "$tmp" "$OUT"
echo "vmlinux.h: $(wc -l < "$OUT") lines, via pinned bpftool $PIN_VERSION"
