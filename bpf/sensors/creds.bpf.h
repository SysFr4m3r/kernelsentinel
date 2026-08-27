/* Credential transitions.
 *
 * commit_creds is where the kernel installs a new credential set, so hooking it
 * catches every transition -- setuid, capset, SUID exec, and kernel paths that
 * never touch a syscall -- from one place.
 *
 * Included by kernelsentinel.bpf.c, which is the single translation unit: all
 * programs share one BPF object so they share its maps. Separate objects would
 * mean separate copies of the ring buffer and the watched-paths trie.
 */
#ifndef __KS_SENSOR_CREDS_H__
#define __KS_SENSOR_CREDS_H__

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

#endif /* __KS_SENSOR_CREDS_H__ */
