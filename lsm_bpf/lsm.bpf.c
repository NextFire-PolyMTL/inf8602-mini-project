#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1
#define S_ISUID 04000

char _license[] SEC("license") = "GPL";

SEC("lsm/inode_copy_up")
int BPF_PROG(restrict_inode_copy_up, struct dentry *src, struct cred **new, int ret)
{
    if (ret)
        return ret;

    struct inode *inode = src->d_inode;
    if (inode->i_mode & S_ISUID && inode->i_uid.val == 0)
        return -EPERM;

    return 0;
}
