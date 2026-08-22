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

static __always_inline void stat_inc(__u32 key)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &key);
	if (v)
		__sync_fetch_and_add(v, 1);
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
