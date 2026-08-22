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

	__u16 type;
	__u16 flags;

	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME];
	char argv[MAX_ARGV]; /* NUL-separated argv, truncated */
};

/* stats map indices */
enum stat_key {
	STAT_EVENTS_EMITTED = 0,
	STAT_RINGBUF_DROPS  = 1,
	STAT_MAX,
};

#endif /* __KERNELSENTINEL_EVENTS_H */
