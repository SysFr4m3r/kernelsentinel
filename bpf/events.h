/* Shared event definitions. Included by the BPF program and mirrored by
 * src/event.rs. Field order is chosen so the struct is naturally aligned with
 * no implicit padding -- keep it that way, and keep the Rust mirror in sync
 * (tests/struct_layout.rs asserts the sizes match). */
#ifndef __KERNELSENTINEL_EVENTS_H
#define __KERNELSENTINEL_EVENTS_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME  256
#define MAX_ARGV      512 /* must stay a power of two: masked for the verifier */

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
};

/* flags */
#define EV_F_TRUNCATED     (1 << 0)
#define EV_F_DEGRADED_PATH (1 << 1)

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

	__u16 type;
	__u16 flags;

	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME]; /* EV_EXEC: exec target; EV_FILE_OPEN: opened path */
	char argv[MAX_ARGV]; /* NUL-separated argv, truncated */
};

/* Longest-prefix-match key for the watched-paths trie. Shared with userspace so
 * the daemon populates the trie with the exact byte layout the BPF side reads. */
#define MAX_WATCH_PATH MAX_FILENAME
struct path_key {
	__u32 prefixlen;              /* bits of `path` to match (LPM) */
	char  path[MAX_WATCH_PATH];
};

/* watched-paths trie value: flags describing when a match should fire */
#define WATCH_ON_WRITE (1u << 0) /* only emit if the file was opened writable */

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
