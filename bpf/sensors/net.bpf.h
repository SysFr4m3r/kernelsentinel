/* Connections to a container runtime control socket.
 *
 * Included by kernelsentinel.bpf.c, which is the single translation unit: all
 * programs share one BPF object so they share its maps. Separate objects would
 * mean separate copies of the ring buffer and the watched-paths trie.
 */
#ifndef __KS_SENSOR_NET_H__
#define __KS_SENSOR_NET_H__

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

#endif /* __KS_SENSOR_NET_H__ */
