/* Connections to a container runtime control socket.
 *
 * Included by kernelsentinel.bpf.c, which is the single translation unit: all
 * programs share one BPF object so they share its maps. Separate objects would
 * mean separate copies of the ring buffer and the watched-paths trie.
 */
#ifndef __KS_SENSOR_NET_H__
#define __KS_SENSOR_NET_H__

/* Match on the name the socket was *bound* as, not the name the caller typed.
 *
 * This sensor used to sit at lsm/socket_connect and prefix-compare the
 * sun_path out of the userspace sockaddr. That is the one part of the
 * operation an attacker chooses, and it was measured: a symlink at
 * /tmp/ks-runtime-alias.sock pointing at /run/docker.sock reached the daemon
 * and produced no event of any kind. Same shape as the hard link to
 * /etc/shadow, same answer -- match on what the kernel knows rather than on
 * what the caller supplied.
 *
 * lsm/unix_stream_connect hands over `other`, the listening socket. A bound
 * AF_UNIX socket carries the struct path it was bound at, so the leaf name
 * here is the one dockerd chose at startup. A symlink, a bind mount or a hard
 * link to the socket all arrive at the same dentry.
 *
 * Two things fall out of that. The daemon may be restarted -- the socket is
 * recreated with a new inode and this still matches, where a map of inodes
 * populated at startup would have gone stale and silently stopped working. And
 * a runtime socket anywhere else on disk is now covered: rootless docker under
 * /run/user/<uid>, podman, k3s nesting containerd under /run/k3s, none of
 * which the old fixed prefixes named.
 */
SEC("lsm/unix_stream_connect")
int BPF_PROG(handle_unix_connect, struct sock *sock, struct sock *other, struct sock *newsk)
{
	struct event *e;
	char name[32] = {};

	struct dentry *d = BPF_CORE_READ((struct unix_sock *)other, path.dentry);
	/* An abstract socket has no filesystem path and no dentry. The runtime
	 * sockets are not abstract, so there is nothing to match. */
	if (!d)
		return 0;
	bpf_probe_read_kernel_str(name, sizeof(name), BPF_CORE_READ(d, d_name.name));

	/* Compares include the terminator, so these are exact rather than
	 * prefix matches: a stray "docker.sock.bak" is not the runtime. Lengths
	 * are compile-time constants and every index is inside the buffer, so
	 * the verifier sees a straight line. */
	int matched = prefix_eq(name, "docker.sock", 12) ||
		      prefix_eq(name, "containerd.sock", 16) ||
		      prefix_eq(name, "podman.sock", 12) ||
		      prefix_eq(name, "crio.sock", 10);
	if (!matched)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		stat_inc(STAT_RINGBUF_DROPS);
		return 0;
	}
	fill_hdr(e, EV_SOCK_CONNECT);
	/* The bound leaf name, like the setcap and path_mknod sensors. The full
	 * path would need bpf_d_path, which an LSM program may only call on
	 * hooks the kernel treats as sleepable, and this is not one. The flag
	 * keeps a bare basename from reading as a full path. */
	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename),
				  BPF_CORE_READ(d, d_name.name));
	e->flags |= EV_F_DEGRADED_PATH;
	bpf_ringbuf_submit(e, 0);
	stat_inc(STAT_EVENTS_EMITTED);
	return 0;
}

#endif /* __KS_SENSOR_NET_H__ */
