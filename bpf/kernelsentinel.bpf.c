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

/* fmode_t and st_mode bits; not BTF types, stable ABI, define here. */
#define FMODE_WRITE 0x2
#define S_ISUID 0x800   /* 04000 */
#define S_ISGID 0x400   /* 02000 */
#define S_IFMT  0xF000
#define S_IFREG 0x8000

#define TMPFS_MAGIC          0x01021994
#define ANON_INODE_FS_MAGIC  0x09041934
#define PTRACE_MODE_ATTACH   0x02   /* the write-capable ptrace modes */
#define AF_UNIX 1

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

	/* A watch opts in to a direction. Reads of credential files are the
	 * theft shape; writes are the persistence shape, and most watched paths
	 * only care about one of the two. Requiring an explicit opt-in keeps a
	 * path like /etc/shadow -- read on every single authentication -- from
	 * flooding userspace merely because it is watched at all.
	 */
	__u32 f_mode = BPF_CORE_READ(file, f_mode);
	if (f_mode & FMODE_WRITE) {
		if (!(*watch & WATCH_ON_WRITE))
			return 0;
	} else if (!(*watch & WATCH_ON_READ)) {
		return 0;
	}

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
SEC("lsm/bprm_check_security")
int BPF_PROG(handle_bprm, struct linux_binprm *bprm)
{
	/* Direct dereference of the trusted bprm argument. bpf_d_path requires a
	 * trusted pointer, and BPF_CORE_READ would launder `file` into an
	 * untrusted scalar (the verifier rejects d_path on it). vmlinux.h enables
	 * preserve_access_index, so these direct loads are still CO-RE relocated. */
	struct file *file = bprm->file;
	unsigned long magic = file->f_inode->i_sb->s_magic;
	unsigned int nlink = file->f_inode->__i_nlink;
	char name[8] = {};
	__u32 source = 0;

	bpf_probe_read_kernel_str(name, sizeof(name), file->f_path.dentry->d_name.name);

	if (name[0] == 'm' && name[1] == 'e' && name[2] == 'm' && name[3] == 'f' &&
	    name[4] == 'd' && name[5] == ':')
		source = EXEC_SRC_MEMFD;
	else if (magic == ANON_INODE_FS_MAGIC)
		source = EXEC_SRC_ANON;
	else if (nlink == 0)
		source = EXEC_SRC_DELETED; /* unlinked binary executed */
	else
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}
	fill_hdr(e, EV_EXEC_ANON);
	e->aux = source;
	if (bpf_d_path(&file->f_path, e->filename, sizeof(e->filename)) < 0)
		e->flags |= EV_F_DEGRADED_PATH;
	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);
	return 0;
}

/* Kernel module load. do_init_module runs after the module is parsed, so the
 * name is the real loaded module name, not an attacker-supplied filename.
 * T1547.006. NOTE: only testable in a VM -- insmod hits the host kernel.
 */
SEC("fexit/do_init_module")
int BPF_PROG(handle_module, struct module *mod)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}
	fill_hdr(e, EV_MODULE);
	bpf_probe_read_kernel_str(e->filename, 64, BPF_CORE_READ(mod, name));
	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);
	return 0;
}

/* lsm/socket_connect fires when a process connects a socket. For AF_UNIX we
 * read the target path from the (already kernel-copied) sockaddr and match it
 * against the privileged control sockets -- the Docker/containerd sockets are a
 * container-escape primitive: a process that can talk to them controls the host
 * container runtime. T1611. Filtered in-kernel to those paths.
 */
/* Fixed-length, fixed-position prefix compare with no branching in the loop --
 * the verifier sees a straight line of `n` comparisons (cheap), unlike a
 * scanning loop over every offset (state explosion). n is a compile-time
 * constant; all indices are < the 108-byte buffer. */
SEC("lsm/socket_connect")
int BPF_PROG(handle_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
	struct event *e;
	char path[108] = {};

	if (BPF_CORE_READ(address, sa_family) != AF_UNIX)
		return 0;
	if (addrlen <= 2)
		return 0;

	struct sockaddr_un *un = (struct sockaddr_un *)address;
	bpf_probe_read_kernel_str(path, sizeof(path), un->sun_path);

	/* Match the runtime control sockets by fixed path prefixes. A scanning
	 * loop over every position blows up the verifier (state explosion ->
	 * "BPF program too large"); fixed-position prefix comparisons are a
	 * straight line it accepts cheaply. These cover the standard socket
	 * locations for docker and containerd. */
	int matched = prefix_eq(path, "/run/docker.sock", 16) ||
		      prefix_eq(path, "/var/run/docker.sock", 20) ||
		      prefix_eq(path, "/run/containerd/", 16) ||
		      prefix_eq(path, "/run/crio/", 10);
	if (!matched)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}
	fill_hdr(e, EV_SOCK_CONNECT);
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), un->sun_path);
	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);
	return 0;
}
