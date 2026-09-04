/* The BPF maps, in one place.
 *
 * Shared by every sensor, which is the reason kernelsentinel.bpf.c is a single
 * translation unit: one object means one ring buffer, one watched-paths trie and
 * one enforcement config. Separate .bpf.c files would compile to separate
 * objects, each with its own copy of all of these.
 */
#ifndef __KS_MAPS_H__
#define __KS_MAPS_H__

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

/* Enforcement configuration, written once by userspace at startup. A map rather
 * than a compile-time constant so the same binary can run detect-only, which is
 * what it does unless explicitly told otherwise. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct enforce_cfg);
} enforce SEC(".maps");

/* Kernel escape hatches, keyed by file identity rather than path. Populated by
 * userspace from stat() at startup. Small and exact: five files. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct file_id);
	__type(value, __u32);
} escape_targets SEC(".maps");

/* Watched files keyed by identity rather than path, so a second name for one is
 * still recognised.
 *
 * The trie above matches the path a file was opened by, which is the path an
 * attacker chooses. `ln /etc/shadow /root/.x && cat /root/.x` reads every hash
 * on the host through a name no prefix lists, and produced no event at all --
 * measured, not supposed. A hard link, a bind mount and the original are the
 * same inode, and that is what this keys on.
 *
 * Only concrete files go in here; a directory prefix like "/etc/cron.d/" has no
 * single inode and stays with the trie. The value is the same watch flags, so
 * direction opt-in works identically whichever way a file was matched.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct file_id);
	__type(value, __u32);
} watched_ids SEC(".maps");

#endif /* __KS_MAPS_H__ */
