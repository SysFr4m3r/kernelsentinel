/* Shared event definitions. Included by the BPF program and mirrored by
 * src/event.rs. Field order is chosen so the struct is naturally aligned with
 * no implicit padding -- keep it that way, and keep the Rust mirror in sync
 * (tests/struct_layout.rs asserts the sizes match). */
#ifndef __KERNELSENTINEL_EVENTS_H
#define __KERNELSENTINEL_EVENTS_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME  256
#define MAX_ARGV      512 /* must stay a power of two: masked for the verifier */
#define MAX_CGROUP_NAME 64

enum event_type {
	EV_EXEC        = 1,
	EV_EXIT        = 2,
	EV_FORK        = 3,
	EV_CRED_CHANGE = 4,
	EV_FILE_OPEN   = 5,
	EV_FILE_MODE   = 6,   /* SUID/SGID bit gained on a regular file */
	EV_SETCAP      = 7,   /* file capabilities set via security.capability xattr */
	EV_PTRACE      = 8,   /* ptrace against another process */
	EV_EXEC_ANON   = 9,   /* execution from memfd / anonymous or deleted file */
	EV_MODULE      = 10,  /* kernel module load */
	EV_SOCK_CONNECT = 11, /* connect() to a watched unix socket */
};

/* flags */
#define EV_F_TRUNCATED     (1 << 0)
#define EV_F_DEGRADED_PATH (1 << 1)
#define EV_F_DENIED        (1 << 2) /* the operation was blocked */
#define EV_F_WOULD_DENY    (1 << 3) /* audit mode: enforcement would have blocked it */
/* The opened file *is* a kernel escape hatch, matched by identity rather than
 * path -- so it is set even when the file was reached through a bind mount at
 * some other location, which is exactly what a container escape does. */
#define EV_F_ESCAPE_TARGET (1 << 4)

struct event {
	__u64 ts_ns;          /* CLOCK_BOOTTIME */
	__u64 cgroup_id;
	__u64 start_boottime; /* with pid, forms the PID-reuse-proof ProcKey */
	__u64 cap_effective;      /* new/current effective capability set */
	__u64 old_cap_effective;  /* EV_CRED_CHANGE only */
	__u64 child_start_boottime; /* EV_FORK only */

	__u32 pid;
	__u32 tgid;
	__u32 ppid;
	__u32 uid;   /* for EV_CRED_CHANGE these four are the *new* values */
	__u32 gid;
	__u32 euid;
	__u32 egid;
	__u32 old_uid;   /* EV_CRED_CHANGE only */
	__u32 old_gid;
	__u32 old_euid;
	__u32 old_egid;
	__u32 exit_code;
	__u32 argv_len;
	__u32 child_pid;          /* EV_FORK: the new task */
	__u32 file_mode;          /* EV_FILE_OPEN: fmode_t; EV_FILE_MODE: new mode */
	__u32 old_file_mode;      /* EV_FILE_MODE: inode i_mode before the change */
	__u32 watch_id;           /* EV_FILE_OPEN: value from the watched-paths trie */
	__u32 target_pid;         /* EV_PTRACE: the traced process */
	__u32 aux;                /* EV_PTRACE: mode; EV_EXEC_ANON: source; EV_MODULE: origin */
	/* Namespace inode numbers, EV_EXEC only. Filled at exec because that is
	 * where a process's identity is established, and filling them on every
	 * event would put three pointer chases in the hot path for nothing. A
	 * containerised process sitting in the host's mount namespace is the
	 * shape of an escape; userspace compares against the host's own inums. */
	__u32 mnt_ns;
	__u32 pid_ns;
	__u32 net_ns;

	__u16 type;
	__u16 flags;

	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME]; /* EV_EXEC: exec target; EV_FILE_OPEN: opened path */
	char argv[MAX_ARGV]; /* NUL-separated argv, truncated */
	char cgroup_name[MAX_CGROUP_NAME]; /* leaf cgroup name, e.g. docker-<id>.scope */
};

/* Longest-prefix-match key for the watched-paths trie. Shared with userspace so
 * the daemon populates the trie with the exact byte layout the BPF side reads. */
#define MAX_WATCH_PATH MAX_FILENAME
struct path_key {
	__u32 prefixlen;              /* bits of `path` to match (LPM) */
	char  path[MAX_WATCH_PATH];
};

/* watched-paths trie value: flags describing when a match should fire */
#define WATCH_ON_WRITE (1u << 0) /* emit when the file was opened writable */
#define WATCH_ON_READ  (1u << 1) /* emit when it was opened read-only */
/* Eligible for denial when the actor is outside the host's mount namespace.
 * Set only on paths where a containerised writer has no legitimate use, since
 * this is the flag that decides whether a syscall fails. */
#define WATCH_DENY_IN_NS (1u << 2)

/* Enforcement is off unless asked for, and audit exists so an operator can see
 * exactly what would break before anything does. A monitoring tool that starts
 * denying syscalls by default is a tool that takes hosts down. */
#define ENFORCE_OFF   0
#define ENFORCE_AUDIT 1
#define ENFORCE_ON    2

/* Identity of a file, independent of where it is mounted.
 *
 * Path matching cannot work for these targets: an escape bind-mounts the host's
 * /proc somewhere else, and bpf_d_path reports the path in the *opening*
 * process's mount namespace -- so the watched prefix never matches. The
 * superblock device plus inode is the same file however it is reached, and a
 * container's own /proc is a different superblock, so this also distinguishes
 * "wrote the host's core_pattern" from "wrote its own". */
struct file_id {
	__u64 ino;
	__u32 dev;
	__u32 _pad;
};

struct enforce_cfg {
	__u32 mode;
	/* The host's mount-namespace inode. Zero disables denial entirely: with
	 * no reference namespace there is no way to tell "inside a container"
	 * from "is the host", and guessing would mean denying on the host. */
	__u32 host_mnt_ns;
};

/* EV_EXEC_ANON `aux` source codes */
#define EXEC_SRC_MEMFD   1  /* dentry name begins "memfd:" */
#define EXEC_SRC_ANON    2  /* anon_inode superblock */
#define EXEC_SRC_DELETED 3  /* file unlinked before exec (i_nlink == 0) */

/* EV_MODULE `aux` origin codes */
#define MOD_INIT   1  /* init_module(2): module image from userspace buffer */
#define MOD_FINIT  2  /* finit_module(2): module image from an fd */

/* stats map indices */
enum stat_key {
	STAT_EVENTS_EMITTED = 0,
	STAT_RINGBUF_DROPS  = 1,
	STAT_MAX,
};

#endif /* __KERNELSENTINEL_EVENTS_H */
