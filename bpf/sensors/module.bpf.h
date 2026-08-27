/* Kernel module loading.
 *
 * Included by kernelsentinel.bpf.c, which is the single translation unit: all
 * programs share one BPF object so they share its maps. Separate objects would
 * mean separate copies of the ring buffer and the watched-paths trie.
 */
#ifndef __KS_SENSOR_MODULE_H__
#define __KS_SENSOR_MODULE_H__

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

#endif /* __KS_SENSOR_MODULE_H__ */
