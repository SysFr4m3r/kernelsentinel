#!/usr/bin/env bash
# Boot a kernel with BPF-LSM *active* and check the sensors actually fire there.
#
# Why this exists: a GitHub runner's kernel has CONFIG_BPF_LSM=y but no `bpf` in
# its LSM list, and a hosted runner cannot be rebooted with a different command
# line. So six of the eleven sensors -- file_open, path_chmod, inode_setxattr,
# ptrace, bprm_check, socket_connect, which is most of the detection surface --
# have never fired anywhere except one developer machine.
#
# The kernel is not the obstacle, the boot parameter is. So take the same kernel
# image and boot it under QEMU with `lsm=...,bpf` appended.
#
# Everything lives in an initramfs: no virtiofs, no 9p, no disk image. Those are
# the parts that vary between kernels (9p is a module on some, absent on others)
# and the parts most likely to fail in a way that looks like a detection bug.
# CONFIG_BLK_DEV_INITRD is universal.
#
#   tests/vm/run.sh [kernel-image]
#
# Uses KVM when /dev/kvm is usable and falls back to emulation, which works and
# is roughly an order of magnitude slower.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${KS_BIN:-$REPO/target/debug/kernelsentinel}"
KERNEL="${1:-/boot/vmlinuz-$(uname -r)}"
LSM="${KS_LSM:-lockdown,capability,landlock,yama,apparmor,bpf}"

die() { echo "vm: $*" >&2; exit 1; }

[[ -x "$BIN" ]] || die "no agent binary at $BIN (cargo build)"
[[ -r "$KERNEL" ]] || die "cannot read kernel $KERNEL (it is often root-only; try sudo, or copy it)"
command -v qemu-system-x86_64 >/dev/null || die "qemu-system-x86_64 not installed"
command -v busybox >/dev/null || die "busybox not installed"
command -v cpio >/dev/null || die "cpio not installed"

WORK="$(mktemp -d)"
ROOT="$WORK/root"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$ROOT"/{bin,sbin,etc,proc,sys,dev,tmp,run,usr/bin,usr/sbin}

# Copy a binary and every shared object it needs. The agent is dynamically
# linked against libelf and libz, so shipping it alone produces a guest that
# boots and cannot run the one thing it was booted for.
copy_with_libs() {
	local src="$1" dst="$2"
	cp "$src" "$ROOT/$dst" || die "copying $src"
	ldd "$src" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*' | sort -u | while read -r lib; do
		[[ -e "$lib" ]] || continue
		mkdir -p "$ROOT$(dirname "$lib")"
		cp -n "$lib" "$ROOT$lib" 2>/dev/null || true
	done
}

copy_with_libs "$(command -v busybox)" bin/busybox
copy_with_libs "$BIN" bin/kernelsentinel
# The loader itself is not listed by ldd as a path on every distro.
for loader in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux-x86-64.so.2; do
	[[ -e "$loader" ]] && { mkdir -p "$ROOT$(dirname "$loader")"; cp -n "$loader" "$ROOT$loader"; }
done

for applet in sh mount umount cat grep sed chmod cp mkdir sleep kill ps ls poweroff env printf; do
	ln -sf /bin/busybox "$ROOT/bin/$applet"
done

# The agent resolves trusted binaries and watched paths from the filesystem, so
# the guest needs enough of one to be a realistic target rather than an empty
# box where every lookup misses.
echo 'ID=vmtest
VERSION_ID=lsm-active' > "$ROOT/etc/os-release"
echo 'root:!:19000:0:99999:7:::' > "$ROOT/etc/shadow"
chmod 600 "$ROOT/etc/shadow"
echo 'root:x:0:0:root:/root:/bin/sh' > "$ROOT/etc/passwd"

cat > "$ROOT/init" <<'INNER'
#!/bin/sh
# PID 1 in the guest. Mount just enough, run the probe, power off. Any exit from
# this script panics the kernel, so it must not return.
mount -t proc     proc     /proc
mount -t sysfs    sysfs    /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs    tmpfs    /tmp
# securityfs is where the LSM list lives, and the agent reads it to decide
# whether the lsm/ sensors are worth counting. Without it mounted the agent sees
# "unknown" and the whole point of this boot is lost.
mkdir -p /sys/kernel/security
mount -t securityfs securityfs /sys/kernel/security 2>/dev/null
# libbpf resolves a tracepoint to its perf event id by reading
# /sys/kernel/tracing/events/<group>/<name>/id. Without tracefs mounted that
# lookup returns ENOENT and the exec sensor cannot attach -- which reads exactly
# like an unsupported kernel and is really a missing mount.
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null

echo "vm: lsm list = $(cat /sys/kernel/security/lsm 2>/dev/null || echo UNREADABLE)"
echo "vm: btf = $(ls /sys/kernel/btf/vmlinux 2>/dev/null || echo ABSENT)"
echo

/bin/kernelsentinel doctor
echo

/bin/kernelsentinel run --json --min-severity info >/tmp/out.ndjson 2>/tmp/err.log &
agent=$!

waited=0
while ! grep -q "ready, streaming events" /tmp/err.log 2>/dev/null; do
	sleep 1
	waited=$((waited + 1))
	if [ $waited -gt 30 ]; then
		echo "vm: the agent never became ready"
		cat /tmp/err.log
		echo "ks-vm-result: FAILED-TO-START"
		poweroff -f
	fi
done
cat /tmp/err.log

# One provocation per sensor family, same three as scripts/compat-probe.sh so
# the results are directly comparable with a bare-metal run.
cp /bin/busybox /tmp/ks-probe
/tmp/ks-probe true 2>/dev/null       # tracepoint exec  -> exec_from_tmp
chmod u+s /tmp/ks-probe              # lsm/path_chmod   -> suid_create
cat /etc/shadow > /dev/null          # lsm/file_open    -> credential_store_read

sleep 2
kill -INT $agent 2>/dev/null
sleep 2

live=""
for pair in "exec:exec_from_tmp" "path_chmod:suid_create" "file_open:credential_store_read"; do
	signal="${pair#*:}"
	if grep -q "\"$signal\"" /tmp/out.ndjson 2>/dev/null; then
		live="${live:+$live,}${pair%%:*}"
	fi
done

active="$(grep -o '[0-9]* of [0-9]* sensors active' /tmp/err.log | head -1)"
echo
echo "ks-vm-result: lsm=$(cat /sys/kernel/security/lsm 2>/dev/null) active=${active:-unknown} live=${live:-none}"
poweroff -f
INNER
chmod +x "$ROOT/init"

( cd "$ROOT" && find . -print0 | cpio --null -o -H newc --quiet ) | gzip -9 > "$WORK/initramfs.gz" \
	|| die "building the initramfs"
echo "vm: initramfs $(du -h "$WORK/initramfs.gz" | cut -f1), kernel $KERNEL"

# Writable /dev/kvm is the whole test: QEMU opens it directly, and a hosted
# runner has the device but not the group, so it is a chmod away rather than
# absent. Emulation is the fallback and is roughly an order of magnitude slower,
# which for a twelve-second boot is an inconvenience, not a blocker.
accel=tcg
[[ -w /dev/kvm ]] && accel=kvm
echo "vm: accelerator $accel"

serial="$WORK/serial.log"
timeout 300 qemu-system-x86_64 \
	-accel "$accel" \
	-m 2048 -smp 2 \
	-kernel "$KERNEL" \
	-initrd "$WORK/initramfs.gz" \
	-append "console=ttyS0 panic=1 lsm=$LSM" \
	-nographic -no-reboot \
	2>&1 | tee "$serial"

echo
result="$(grep -m1 '^ks-vm-result:' "$serial")"
if [[ -z "$result" ]]; then
	die "the guest produced no result line -- see the boot log above"
fi
echo "$result"

# The whole reason for this boot: the lsm/ sensors must actually fire. A run
# where only exec answered means the kernel came up without bpf in its LSM list,
# so nothing new was tested and reporting success would be worse than failing.
case "$result" in
	*live=*path_chmod*|*live=*file_open*) ;;
	*) die "no lsm/ sensor fired -- this boot tested nothing the runner does not already cover" ;;
esac
echo "vm: the lsm/ sensors fired on a kernel booted with bpf in the LSM list"
