#include <linux/fs.h>
#include <linux/slab.h>
#include "vtfs.h"

struct inode *vtfs_iget(struct super_block *sb, u64 backend_ino, umode_t mode,
                        loff_t size, unsigned int nlink)
{
    struct inode *inode;
    struct vtfs_inode_info *vi;
    struct vtfs_sb_info *sbi = VTFS_SB(sb);

    inode = new_inode(sb);
    if (!inode)
        return ERR_PTR(-ENOMEM);

    vi = VTFS_I(inode);
    vi->backend_ino = backend_ino;
    vi->cached_size = size;

    inode->i_ino = get_next_ino();
    
    if (sbi->readonly) {
        mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
    }
    
    vtfs_inode_init_owner(VTFS_NOP_IDMAP, inode, NULL, mode);
    inode->i_size = size;
    inode->i_blocks = (size + 511) >> 9;
    set_nlink(inode, nlink);

    vtfs_set_time(inode);

    if (S_ISDIR(mode)) {
        inode->i_op = &vtfs_dir_inode_ops;
        inode->i_fop = &vtfs_dir_ops;
    } else if (S_ISREG(mode)) {
        inode->i_op = &vtfs_file_inode_ops;
        inode->i_fop = &vtfs_file_ops;
    }

    return inode;
}

static int vtfs_setattr(VTFS_IDMAP_TYPE idmap, struct dentry *dentry,
                        struct iattr *attr)
{
    struct inode *inode = d_inode(dentry);
    struct vtfs_sb_info *sbi = VTFS_SB(inode->i_sb);
    struct vtfs_inode_info *vi = VTFS_I(inode);
    int ret;

    if (sbi->readonly)
        return -EROFS;

    if (attr->ia_valid & ATTR_SIZE) {
        ret = vtfs_proto_truncate(sbi, vi->backend_ino, attr->ia_size);
        if (ret < 0)
            return ret;

        i_size_write(inode, attr->ia_size);
        inode->i_blocks = (attr->ia_size + 511) >> 9;
        vi->cached_size = attr->ia_size;
    }

    setattr_copy(idmap, inode, attr);
    return 0;
}

static int vtfs_getattr(VTFS_GETATTR_ARGS)
{
    struct inode *inode = VTFS_GETATTR_INODE;
    struct vtfs_sb_info *sbi = VTFS_SB(inode->i_sb);
    struct vtfs_inode_info *vi = VTFS_I(inode);
    umode_t mode;
    loff_t size;
    unsigned int nlink;
    int ret;

    ret = vtfs_proto_getattr(sbi, vi->backend_ino, &mode, &size, &nlink);
    if (ret == 0) {
        if (sbi->readonly) {
            mode &= ~(S_IWUSR | S_IWGRP | S_IWOTH);
        }
        inode->i_mode = mode;
        inode->i_size = size;
        inode->i_blocks = (size + 511) >> 9;
        set_nlink(inode, nlink);
        vi->cached_size = size;
    }

    vtfs_generic_fillattr(idmap, request_mask, inode, stat);
    return 0;
}


const struct inode_operations vtfs_file_inode_ops = {
    .getattr = vtfs_getattr,
    .setattr = vtfs_setattr,
};