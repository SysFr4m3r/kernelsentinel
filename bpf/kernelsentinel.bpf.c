// SPDX-License-Identifier: GPL-2.0
/* KernelSentinel BPF sensors.
 *
 * GPL-2.0 is not a formality here: bpf_probe_read_kernel_str() and later
 * bpf_d_path() are GPL-only helpers and the verifier rejects the program
 * without this license string. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "events.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/* fmode_t bit; not a BTF type, so define it here. Stable ABI. */
#define FMODE_WRITE 0x2

/* Paths the daemon asked us to watch. LPM_TRIE so one entry like "/etc/cron.d/"
 * matches every file beneath it, and the match happens in-kernel: shipping
 * every file_open to userspace would melt the host. */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct path_key);
	__type(value, __u32);
	__uint(max_entries, 1024);
	__uint(map_flags, BPF_F_NO_PREALLOC); /* required for LPM_TRIE */
} watched_paths SEC(".maps");

static __always_inline void stat_inc(__u32 key)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &key);
	if (v)
		__sync_fetch_and_add(v, 1);
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
	e->watch_id = 0;
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

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct event *e;
	unsigned int fname_off;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}

	fill_hdr(e, EV_EXEC);

	/* __data_loc: low 16 bits are the offset from the start of the record */
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
				  (void *)ctx + fname_off);

	fill_argv(e);

	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);
	return 0;
}

/* Raw tracepoints hand us the task_struct directly, which regular tracepoints
 * do not. That matters here: a pid alone cannot tell a thread from a process,
 * and we only want process-level fork/exit in the graph. */
SEC("raw_tp/sched_process_fork")
int BPF_PROG(handle_fork, struct task_struct *parent, struct task_struct *child)
{
	struct event *e;
	__u32 child_pid = BPF_CORE_READ(child, pid);
	__u32 child_tgid = BPF_CORE_READ(child, tgid);

	/* pid != tgid means a new thread in an existing process, not a fork. */
	if (child_pid != child_tgid)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}

	fill_hdr(e, EV_FORK);
	e->child_pid = child_tgid;
	e->child_start_boottime = BPF_CORE_READ(child, start_boottime);

	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);
	return 0;
}

SEC("raw_tp/sched_process_exit")
int BPF_PROG(handle_exit, struct task_struct *p)
{
	struct event *e;
	__u32 pid = BPF_CORE_READ(p, pid);
	__u32 tgid = BPF_CORE_READ(p, tgid);

	/* Only the thread group leader's exit ends the process. */
	if (pid != tgid)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}

	fill_hdr(e, EV_EXIT);
	e->start_boottime = BPF_CORE_READ(p, start_boottime);
	e->exit_code = (__u32)BPF_CORE_READ(p, exit_code) >> 8;

	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);
	return 0;
}

/* fentry, not fexit: on entry current_cred() is still the *old* credential set
 * and `new` is what is about to be installed, so both sides are visible.
 *
 * Hooking commit_creds rather than the setuid syscalls catches every
 * credential transition -- setuid/setresuid/capset, SUID exec, and kernel
 * paths that never touch a syscall -- from one place.
 */
SEC("fentry/commit_creds")
int BPF_PROG(handle_commit_creds, struct cred *new)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
	const struct cred *old = BPF_CORE_READ(task, cred);
	struct event *e;

	__u32 old_uid = BPF_CORE_READ(old, uid.val);
	__u32 old_gid = BPF_CORE_READ(old, gid.val);
	__u32 old_euid = BPF_CORE_READ(old, euid.val);
	__u32 old_egid = BPF_CORE_READ(old, egid.val);
	__u32 new_uid = BPF_CORE_READ(new, uid.val);
	__u32 new_gid = BPF_CORE_READ(new, gid.val);
	__u32 new_euid = BPF_CORE_READ(new, euid.val);
	__u32 new_egid = BPF_CORE_READ(new, egid.val);

	__u64 old_cap = read_cap(&old->cap_effective);
	__u64 new_cap = read_cap(&new->cap_effective);

	/* Every execve calls commit_creds, almost always installing identical
	 * credentials. Emitting those would bury the real transitions, so drop
	 * no-ops in the kernel rather than filtering in userspace. */
	if (old_uid == new_uid && old_gid == new_gid && old_euid == new_euid &&
	    old_egid == new_egid && old_cap == new_cap)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}

	fill_hdr(e, EV_CRED_CHANGE);
	e->uid = new_uid;
	e->gid = new_gid;
	e->euid = new_euid;
	e->egid = new_egid;
	e->old_uid = old_uid;
	e->old_gid = old_gid;
	e->old_euid = old_euid;
	e->old_egid = old_egid;
	e->cap_effective = new_cap;
	e->old_cap_effective = old_cap;

	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);
	return 0;
}

/* lsm/file_open runs after the kernel has resolved the file, so we get a real
 * struct file and can call bpf_d_path() -- the path is canonical and there is
 * no TOCTOU window, unlike reading a userspace pointer at sys_enter_openat.
 *
 * Detect-only: this hook can return an error to *deny* the open, but we always
 * return 0. Blocking is an explicit v2 decision, not a side effect.
 */
SEC("lsm/file_open")
int BPF_PROG(handle_file_open, struct file *file)
{
	struct path_key key = {};
	struct event *e;
	__u32 *watch;
	long len;

	/* bpf_d_path is GPL-only and allowlisted to a set of hooks that take a
	 * struct path; file_open is one of them. */
	len = bpf_d_path(&file->f_path, key.path, sizeof(key.path));
	if (len < 0)
		return 0;

	/* LPM matches on bits of the key; exclude the trailing NUL so a stored
	 * prefix like "/etc/" (40 bits) matches "/etc/passwd". Clamp so a
	 * pathological length can never drive prefixlen past the buffer -- this
	 * is exactly the silent-overflow class of bug seen elsewhere here. */
	if (len < 1)
		return 0;
	if (len > (long)sizeof(key.path))
		len = sizeof(key.path);
	key.prefixlen = (__u32)(len - 1) * 8;

	watch = bpf_map_lookup_elem(&watched_paths, &key);
	if (!watch)
		return 0;

	__u32 f_mode = BPF_CORE_READ(file, f_mode);
	if ((*watch & WATCH_ON_WRITE) && !(f_mode & FMODE_WRITE))
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}

	fill_hdr(e, EV_FILE_OPEN);
	e->file_mode = f_mode;
	e->watch_id = *watch;
	__builtin_memcpy(e->filename, key.path, sizeof(e->filename));

	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);
	return 0;
}
