/*
 * BPF program which contains the LSM hook implementation.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "printk.bpf.h"

#define EPERM 1
#define S_ISUID 04000

char LICENSE[] SEC("license") = "GPL";

/**
 * LSM_HOOK(int, 0, inode_copy_up, struct dentry *src, struct cred **new)
 *
 * https://github.com/torvalds/linux/blob/b0546776ad3f332e215cebc0b063ba4351971cca/include/linux/lsm_hook_defs.h#L178
 * https://docs.kernel.org/security/lsm-development.html#c.security_inode_copy_up
 */
SEC("lsm/inode_copy_up")
int BPF_PROG(restrict_inode_copy_up, struct dentry *src, struct cred **new, int ret)
{
    if (ret != 0)
    {
        return ret;
    }

    struct inode *inode = src->d_inode;

    // If the file has the setuid bit set and the owner is root,
    // deny the copy-up operation
    if ((inode->i_mode & S_ISUID) && (inode->i_uid.val == 0))
    {
        bpf_printk("lsm_bpf: inode_copy_up: deny copy-up of setuid root file \"%s\"\n", src->d_name.name);
        return -EPERM;
    }

    return 0;
}
