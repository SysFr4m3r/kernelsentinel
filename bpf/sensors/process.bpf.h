/* Process lifecycle: exec, fork and exit.
 *
 * The spine of the process graph -- everything else attributes behaviour to a
 * process these three established.
 *
 * Included by kernelsentinel.bpf.c, which is the single translation unit: all
 * programs share one BPF object so they share its maps. Separate objects would
 * mean separate copies of the ring buffer and the watched-paths trie.
 */
#ifndef __KS_SENSOR_PROCESS_H__
#define __KS_SENSOR_PROCESS_H__

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct event *e;
	struct task_struct *task;
	unsigned int fname_off;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}

	task = (struct task_struct *)bpf_get_current_task_btf();
	fill_hdr(e, EV_EXEC);
	fill_ns(e, task);

	/* sched_process_exec fires after the new image is installed, so exe_file
	 * is already the binary that is now running rather than the one that
	 * called execve. A kernel thread has no mm and these read as zero, which
	 * userspace treats as "unknown" and never as a match. */
	e->exe_ino = BPF_CORE_READ(task, mm, exe_file, f_inode, i_ino);
	e->exe_dev = BPF_CORE_READ(task, mm, exe_file, f_inode, i_sb, s_dev);

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

#endif /* __KS_SENSOR_PROCESS_H__ */
