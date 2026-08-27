/* Execution of a binary that never touched disk.
 *
 * Included by kernelsentinel.bpf.c, which is the single translation unit: all
 * programs share one BPF object so they share its maps. Separate objects would
 * mean separate copies of the ring buffer and the watched-paths trie.
 */
#ifndef __KS_SENSOR_EXEC_ANON_H__
#define __KS_SENSOR_EXEC_ANON_H__

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

#endif /* __KS_SENSOR_EXEC_ANON_H__ */
