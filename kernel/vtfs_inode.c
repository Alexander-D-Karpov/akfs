#include <linux/fs.h>
#include <linux/slab.h>
#include "vtfs.h"

struct inode *vtfs_iget(struct super_block *sb, u64 backend_ino, umode_t mode,
                        loff_t size, unsigned int nlink)
{
    struct inode *inode;
    struct vtfs_inode_info *vi;

    inode = new_inode(sb);
    if (!inode)
        return ERR_PTR(-ENOMEM);

    vi = VTFS_I(inode);
    vi->backend_ino = backend_ino;

    inode->i_ino = get_next_ino();
    vtfs_inode_init_owner(VTFS_NOP_IDMAP, inode, NULL, mode);
    inode->i_size = size;
    inode->i_blocks = (size + 511) >> 9;
    set_nlink(inode, nlink);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
    simple_inode_init_ts(inode);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    inode->i_atime = inode->i_mtime = inode_set_ctime_current(inode);
#else
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
#endif

    if (S_ISDIR(mode)) {
        inode->i_op = &vtfs_dir_inode_ops;
        inode->i_fop = &vtfs_dir_ops;
    } else if (S_ISREG(mode)) {
        inode->i_op = &vtfs_file_inode_ops;
        inode->i_fop = &vtfs_file_ops;
    }

    return inode;
}