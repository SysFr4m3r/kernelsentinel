/* Constants and helpers shared by the sensors.
 *
 * Everything here is __always_inline: BPF has no function call to a helper of
 * our own that the verifier would accept as a separate body, so these are
 * textually inlined into each program that uses them.
 */
#ifndef __KS_COMMON_H__
#define __KS_COMMON_H__

/* fmode_t and st_mode bits; not BTF types, stable ABI, define here. */
#define FMODE_WRITE 0x2
/* vmlinux.h carries no errno definitions; an LSM hook denies by returning the
 * negative errno the syscall should fail with. */
#define EPERM 1
#define S_ISUID 0x800   /* 04000 */
#define S_ISGID 0x400   /* 02000 */
#define S_IFMT  0xF000
#define S_IFREG 0x8000


#define TMPFS_MAGIC          0x01021994
#define ANON_INODE_FS_MAGIC  0x09041934
#define PTRACE_MODE_ATTACH   0x02   /* the write-capable ptrace modes */
#define AF_UNIX 1




static __always_inline void stat_inc(__u32 key)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &key);
	if (v)
		__sync_fetch_and_add(v, 1);
}

/* Fixed-length byte compare.
 *
 * Not __builtin_memcmp: with a length clang cannot fold, it lowers that to a
 * call to libc memcmp, and there is no libc in a BPF program -- the BPF linker
 * rejects the object with "failed to find BTF info for global/extern symbol
 * 'memcmp'". Newer clang inlines short compares and hides the problem, so this
 * only surfaces on an older toolchain. An explicit unrolled loop compiles the
 * same way everywhere, and is branchless, which the verifier also prefers.
 */
static __always_inline int prefix_eq(const char *p, const char *pre, int n)
{
	int ok = 1;
#pragma unroll
	for (int i = 0; i < n; i++)
		ok &= (p[i] == pre[i]);
	return ok;
}

/* kernel_cap_t is `struct { u64 val; }` since 6.3 and `struct { u32 cap[2]; }`
 * before that. Read it CO-RE-safely so one binary works across both. */
static __always_inline __u64 read_cap(const kernel_cap_t *cap)
{
	__u64 val = 0;

	if (bpf_core_field_exists(cap->val)) {
		val = BPF_CORE_READ(cap, val);
	} else {
		/* Older layout: two 32-bit halves. Accessed through a compatible
		 * view so CO-RE relocates rather than the verifier rejecting. */
		struct kernel_cap_legacy {
			__u32 cap[2];
		} *legacy = (void *)cap;
		__u32 lo = 0, hi = 0;

		bpf_core_read(&lo, sizeof(lo), &legacy->cap[0]);
		bpf_core_read(&hi, sizeof(hi), &legacy->cap[1]);
		val = ((__u64)hi << 32) | lo;
	}
	return val;
}

/* Should this operation be denied, and is denial armed?
 *
 * Returns ENFORCE_OFF (allow), ENFORCE_AUDIT (would deny, but allow) or
 * ENFORCE_ON (deny). Every uncertain path returns OFF: no config, no host
 * namespace, no readable namespace on the task. Failing open is the only
 * acceptable default for code that can make syscalls fail -- a monitoring agent
 * that blocks something because it could not read a pointer is worse than one
 * that misses a detection.
 */
static __always_inline __u32 deny_decision(int is_escape_target)
{
	__u32 zero = 0, mnt = 0;
	struct enforce_cfg *cfg;
	struct task_struct *task;

	if (!is_escape_target)
		return ENFORCE_OFF;

	cfg = bpf_map_lookup_elem(&enforce, &zero);
	if (!cfg || cfg->mode == ENFORCE_OFF || !cfg->host_mnt_ns)
		return ENFORCE_OFF;

	if (!bpf_core_type_exists(struct mnt_namespace))
		return ENFORCE_OFF;

	task = (struct task_struct *)bpf_get_current_task_btf();
	mnt = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	/* Unreadable namespace, or the host itself: allow. Only a task provably
	 * in a *different* mount namespace is a candidate. */
	if (!mnt || mnt == cfg->host_mnt_ns)
		return ENFORCE_OFF;

	return cfg->mode;
}

/* Namespace inode numbers for a task.
 *
 * Only called for exec: three pointer chases per event would be real cost in
 * the hot path, and a process's namespaces are established at exec, not per
 * event. mnt_namespace is an fs-internal type, so its presence in a target
 * kernel's BTF is guarded rather than assumed -- an unguarded relocation
 * against a missing type makes the whole program fail to load.
 */
static __always_inline void fill_ns(struct event *e, struct task_struct *task)
{
	struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);

	if (!nsp)
		return;
	if (bpf_core_type_exists(struct mnt_namespace))
		e->mnt_ns = BPF_CORE_READ(nsp, mnt_ns, ns.inum);
	e->pid_ns = BPF_CORE_READ(nsp, pid_ns_for_children, ns.inum);
	e->net_ns = BPF_CORE_READ(nsp, net_ns, ns.inum);
}

/* Fill the common header from the current task. */
static __always_inline void fill_hdr(struct event *e, __u16 type)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	__u64 uid_gid = bpf_get_current_uid_gid();

	e->ts_ns = bpf_ktime_get_boot_ns();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->type = type;
	e->flags = 0;
	e->exit_code = 0;
	e->argv_len = 0;
	e->child_pid = 0;
	e->child_start_boottime = 0;
	e->file_mode = 0;
	e->old_file_mode = 0;
	e->watch_id = 0;
	e->target_pid = 0;
	e->aux = 0;
	e->mnt_ns = 0;
	e->pid_ns = 0;
	e->net_ns = 0;
	e->old_uid = 0;
	e->old_gid = 0;
	e->old_euid = 0;
	e->old_egid = 0;
	e->cap_effective = read_cap(&BPF_CORE_READ(task, cred)->cap_effective);
	e->old_cap_effective = 0;
	e->filename[0] = '\0';
	e->argv[0] = '\0';

	e->uid = (__u32)uid_gid;
	e->gid = (__u32)(uid_gid >> 32);
	e->pid = (__u32)bpf_get_current_pid_tgid();
	e->tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->start_boottime = BPF_CORE_READ(task, start_boottime);
	e->euid = BPF_CORE_READ(task, cred, euid.val);
	e->egid = BPF_CORE_READ(task, cred, egid.val);

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Capture the leaf cgroup name in-kernel, where the cgroup is guaranteed to
	 * exist. Resolving cgroup_id -> name in userspace races with container
	 * teardown: an ephemeral --rm container's cgroup dir is gone before the
	 * event is processed. Reading it here is race-free. Userspace parses the
	 * container id out of names like "docker-<id>.scope". */
	e->cgroup_name[0] = '\0';
	const char *cname = BPF_CORE_READ(task, cgroups, dfl_cgrp, kn, name);
	if (cname)
		bpf_probe_read_kernel_str(e->cgroup_name, sizeof(e->cgroup_name), cname);
}

/* argv is read from the *new* mm after the exec has completed, so there is no
 * TOCTOU window on a userspace pointer the way there is at sys_enter_execve. */
static __always_inline void fill_argv(struct event *e)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	unsigned long arg_start = BPF_CORE_READ(task, mm, arg_start);
	unsigned long arg_end = BPF_CORE_READ(task, mm, arg_end);
	__u32 len;

	if (!arg_start || arg_end <= arg_start)
		return;

	len = (__u32)(arg_end - arg_start);
	if (len >= MAX_ARGV) {
		/* Clamp to MAX_ARGV-1, not MAX_ARGV: the mask below is what proves
		 * the bound to the verifier, and masking MAX_ARGV itself yields 0,
		 * which would silently drop exactly the longest command lines. */
		len = MAX_ARGV - 1;
		e->flags |= EV_F_TRUNCATED;
	}
	len &= (MAX_ARGV - 1);
	if (len == 0)
		return;

	if (bpf_probe_read_user(e->argv, len, (void *)arg_start) == 0)
		e->argv_len = len;
}

#endif /* __KS_COMMON_H__ */
