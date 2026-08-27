/* Debugger attachment and cross-uid /proc memory access.
 *
 * Included by kernelsentinel.bpf.c, which is the single translation unit: all
 * programs share one BPF object so they share its maps. Separate objects would
 * mean separate copies of the ring buffer and the watched-paths trie.
 */
#ifndef __KS_SENSOR_PTRACE_H__
#define __KS_SENSOR_PTRACE_H__

/* ptrace_access_check fires when one task attaches to or reads another. It is
 * how debuggers, injectors, and /proc/<pid>/mem readers reach another process.
 * current is the tracer; `child` is the target. T1055.008.
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(handle_ptrace, struct task_struct *child, unsigned int mode)
{
	__u32 target = BPF_CORE_READ(child, tgid);
	struct event *e;

	/* Ignore self-inspection: a thread poking its own group is not attack
	 * shaped, and it stops the daemon from noticing its own /proc reads. */
	if (target == (__u32)(bpf_get_current_pid_tgid() >> 32))
		return 0;

	/* ptrace_access_check fires constantly for same-privilege introspection --
	 * ps, top, systemd reading /proc, container runtimes reading their own
	 * children. Filter to the two shapes that actually matter in-kernel:
	 *   - ATTACH mode: real ptrace attach, and /proc/<pid>/mem reads
	 *   - a cross-uid read: one euid reading another's memory/environ/maps,
	 *     the credential-theft shape (T1003 / T1552)
	 * Same-uid, read-only access is dropped. This is where the flood lives. */
	__u32 tracer_euid = BPF_CORE_READ(
		(struct task_struct *)bpf_get_current_task_btf(), cred, euid.val);
	__u32 target_euid = BPF_CORE_READ(child, cred, euid.val);
	if (!(mode & PTRACE_MODE_ATTACH) && tracer_euid == target_euid)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}
	fill_hdr(e, EV_PTRACE);
	e->target_pid = target;
	e->aux = mode;
	bpf_probe_read_kernel_str(e->filename, TASK_COMM_LEN,
				  BPF_CORE_READ(child, comm));
	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);
	return 0;
}

/* Detect execution that never touched disk. bprm_check_security runs during
 * execve with the resolved binary in bprm->file. The robust signal is the
 * dentry name beginning "memfd:" (set by memfd_create) or an anonymous
 * superblock -- NOT the /proc/self/fd/ path string, which is trivially evaded
 * by re-opening the descriptor elsewhere. T1620.
 */

#endif /* __KS_SENSOR_PTRACE_H__ */
