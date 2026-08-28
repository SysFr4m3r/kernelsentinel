/* File sensors: opens of watched paths, new SUID bits, and file capabilities.
 *
 * All three take a struct path or dentry, so paths are resolved by the kernel
 * rather than read from a userspace pointer at syscall entry.
 *
 * Included by kernelsentinel.bpf.c, which is the single translation unit: all
 * programs share one BPF object so they share its maps. Separate objects would
 * mean separate copies of the ring buffer and the watched-paths trie.
 */
#ifndef __KS_SENSOR_FILE_H__
#define __KS_SENSOR_FILE_H__

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
	struct file_id fid = {};
	struct event *e;
	/* Both map results are carried as scalars rather than as pointers.
	 *
	 * Nulling a map pointer to mean "no match" reads naturally and is a load
	 * failure waiting to happen: clang is free to compile
	 *
	 *     if (!(flags & WANT)) p = NULL;
	 *
	 * into a branchless select -- build a 0/-1 mask from the test and AND it
	 * into the pointer -- and the verifier rejects that outright with
	 * "bitwise operator &= on pointer prohibited". Whether it does so depends
	 * on the compiler, so the same source builds a loadable object on one
	 * machine and an unloadable one on another. Keeping the decision on
	 * scalars removes the choice.
	 *
	 * watch_flags is 0 when nothing matched: every watch carries at least one
	 * direction bit, so a stored value is never 0 (asserted in
	 * watchlist::tests::every_watch_has_a_direction).
	 */
	__u32 watch_flags = 0;
	int is_hatch = 0;
	long len;

	__u32 f_mode = BPF_CORE_READ(file, f_mode);

	/* Identity check first, and only for writable opens.
	 *
	 * This is what catches an escape: the container bind-mounts the host's
	 * /proc somewhere else, so bpf_d_path reports a path the watched-prefix
	 * trie will never match. The superblock device and inode are the same
	 * file however it is reached. Restricted to writes because these targets
	 * are only interesting when written, which keeps one extra hash lookup
	 * off the far more common read path.
	 */
	if (f_mode & FMODE_WRITE) {
		fid.ino = BPF_CORE_READ(file, f_inode, i_ino);
		fid.dev = BPF_CORE_READ(file, f_inode, i_sb, s_dev);
		is_hatch = bpf_map_lookup_elem(&escape_targets, &fid) != NULL;
	}

	/* bpf_d_path is GPL-only and allowlisted to a set of hooks that take a
	 * struct path; file_open is one of them. */
	len = bpf_d_path(&file->f_path, key.path, sizeof(key.path));
	if (len < 1)
		return 0;
	if (len > (long)sizeof(key.path))
		len = sizeof(key.path);
	key.prefixlen = (__u32)(len - 1) * 8;

	__u32 *w = bpf_map_lookup_elem(&watched_paths, &key);
	if (w) {
		/* Read the flags out once; every decision below is on the scalar. */
		__u32 flags = *w;

		/* A watch opts in to a direction. Reads of credential files are
		 * the theft shape; writes are the persistence shape, and most
		 * watched paths care about only one. Requiring an explicit
		 * opt-in keeps a path like /etc/shadow -- read on every single
		 * authentication -- from flooding userspace merely because it
		 * is watched at all. */
		if (f_mode & FMODE_WRITE) {
			if (flags & WATCH_ON_WRITE)
				watch_flags = flags;
		} else if (flags & WATCH_ON_READ) {
			watch_flags = flags;
		}
	}

	if (!watch_flags && !is_hatch)
		return 0;

	/* Decided before the event is submitted, so a denial is always recorded
	 * -- an operation blocked without a trace is the worst of both worlds. */
	__u32 decision = deny_decision(is_hatch);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		/* Never deny an operation we could not record. */
		return 0;
	}

	fill_hdr(e, EV_FILE_OPEN);
	e->file_mode = f_mode;
	e->watch_id = watch_flags;
	if (is_hatch)
		e->flags |= EV_F_ESCAPE_TARGET;
	if (decision == ENFORCE_ON)
		e->flags |= EV_F_DENIED;
	else if (decision == ENFORCE_AUDIT)
		e->flags |= EV_F_WOULD_DENY;
	__builtin_memcpy(e->filename, key.path, sizeof(e->filename));

	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);

	return decision == ENFORCE_ON ? -EPERM : 0;
}

/* lsm/path_chmod fires before the new mode is applied, so the inode still
 * carries the old mode and the hook argument carries the new one -- exactly the
 * before/after needed to catch a 0 -> SUID transition. Requires
 * CONFIG_SECURITY_PATH; on kernels without it, inode_setattr is the portable
 * fallback (dentry walk instead of bpf_d_path). path_chmod takes a struct path,
 * so bpf_d_path resolves the canonical path with no dentry walk here.
 *
 * A newly-SUID root binary is the classic local-privilege-escalation artifact
 * (T1548.001). The signal is the *transition*: a binary that was already SUID
 * getting re-chmod'd is not interesting; one gaining the bit is.
 */

/* lsm/path_chmod fires before the new mode is applied, so the inode still
 * carries the old mode and the hook argument carries the new one -- exactly the
 * before/after needed to catch a 0 -> SUID transition. Requires
 * CONFIG_SECURITY_PATH; on kernels without it, inode_setattr is the portable
 * fallback (dentry walk instead of bpf_d_path). path_chmod takes a struct path,
 * so bpf_d_path resolves the canonical path with no dentry walk here.
 *
 * A newly-SUID root binary is the classic local-privilege-escalation artifact
 * (T1548.001). The signal is the *transition*: a binary that was already SUID
 * getting re-chmod'd is not interesting; one gaining the bit is.
 */
SEC("lsm/path_chmod")
int BPF_PROG(handle_path_chmod, struct path *path, umode_t new_mode)
{
	struct dentry *dentry = BPF_CORE_READ(path, dentry);
	__u32 inode_mode = BPF_CORE_READ(dentry, d_inode, i_mode);
	struct event *e;

	/* Only regular files. SGID on a directory is normal and common. */
	if ((inode_mode & S_IFMT) != S_IFREG)
		return 0;

	__u32 gained_suid = (new_mode & S_ISUID) && !(inode_mode & S_ISUID);
	__u32 gained_sgid = (new_mode & S_ISGID) && !(inode_mode & S_ISGID);
	if (!gained_suid && !gained_sgid)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}

	fill_hdr(e, EV_FILE_MODE);
	e->old_file_mode = inode_mode;
	e->file_mode = new_mode;
	if (bpf_d_path(path, e->filename, sizeof(e->filename)) < 0)
		e->flags |= EV_F_DEGRADED_PATH;

	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);
	return 0;
}

/* setcap writes file capabilities through the security.capability xattr. This
 * is the real privilege-escalation signal behind `setcap`: a binary can gain
 * CAP_SYS_ADMIN with no SUID bit and no visible mode change. T1548.
 * The hook fires for every setxattr, so filter to the capability name in-kernel.
 */

/* setcap writes file capabilities through the security.capability xattr. This
 * is the real privilege-escalation signal behind `setcap`: a binary can gain
 * CAP_SYS_ADMIN with no SUID bit and no visible mode change. T1548.
 * The hook fires for every setxattr, so filter to the capability name in-kernel.
 */
SEC("lsm/inode_setxattr")
int BPF_PROG(handle_setxattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name)
{
	char xattr[20] = {};
	struct event *e;

	if (bpf_probe_read_kernel_str(xattr, sizeof(xattr), name) < 0)
		return 0;

	/* "security.capability" -- compare enough to be unambiguous. */
	if (!prefix_eq(xattr, "security.capability", 19))
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}
	fill_hdr(e, EV_SETCAP);
	/* bpf_d_path is not available on this hook (dentry, no struct path), so
	 * record the leaf name; userspace can enrich via (dev, inode) later. */
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
				  BPF_CORE_READ(dentry, d_name.name));
	e->flags |= EV_F_DEGRADED_PATH;
	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);
	return 0;
}

/* ptrace_access_check fires when one task attaches to or reads another. It is
 * how debuggers, injectors, and /proc/<pid>/mem readers reach another process.
 * current is the tracer; `child` is the target. T1055.008.
 */

#endif /* __KS_SENSOR_FILE_H__ */
