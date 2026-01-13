#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include "vtfs.h"

static struct dentry *vtfs_lookup(struct inode *dir, struct dentry *dentry,
                                   unsigned int flags)
{
    struct vtfs_sb_info *sbi = VTFS_SB(dir->i_sb);
    struct vtfs_inode_info *dir_vi = VTFS_I(dir);
    struct inode *inode = NULL;
    u64 ino;
    umode_t mode;
    loff_t size;
    unsigned int nlink;
    int ret;

    if (dentry->d_name.len > VTFS_NAME_MAX)
        return ERR_PTR(-ENAMETOOLONG);

    ret = vtfs_proto_lookup(sbi, dir_vi->backend_ino, dentry->d_name.name,
                            &ino, &mode, &size, &nlink);
    if (ret == -ENOENT) {
        d_add(dentry, NULL);
        return NULL;
    }
    if (ret < 0)
        return ERR_PTR(ret);

    inode = vtfs_iget(dir->i_sb, ino, mode, size, nlink);
    if (IS_ERR(inode))
        return ERR_CAST(inode);

    return d_splice_alias(inode, dentry);
}

static int vtfs_create(VTFS_IDMAP_TYPE idmap, struct inode *dir,
                       struct dentry *dentry, umode_t mode, bool excl)
{
    struct vtfs_sb_info *sbi = VTFS_SB(dir->i_sb);
    struct vtfs_inode_info *dir_vi = VTFS_I(dir);
    struct inode *inode;
    u64 ino;
    int ret;

    if (sbi->readonly)
        return -EROFS;

    ret = vtfs_proto_create(sbi, dir_vi->backend_ino, dentry->d_name.name,
                            mode | S_IFREG, &ino);
    if (ret < 0)
        return ret;

    inode = vtfs_iget(dir->i_sb, ino, mode | S_IFREG, 0, 1);
    if (IS_ERR(inode))
        return PTR_ERR(inode);

    vtfs_update_time(dir);
    d_instantiate(dentry, inode);
    return 0;
}

static VTFS_MKDIR_RETTYPE vtfs_mkdir(VTFS_IDMAP_TYPE idmap, struct inode *dir,
                                      struct dentry *dentry, umode_t mode)
{
    struct vtfs_sb_info *sbi = VTFS_SB(dir->i_sb);
    struct vtfs_inode_info *dir_vi = VTFS_I(dir);
    struct inode *inode;
    u64 ino;
    int ret;

    if (sbi->readonly)
        return VTFS_MKDIR_RET_ERR(-EROFS);

    ret = vtfs_proto_mkdir(sbi, dir_vi->backend_ino, dentry->d_name.name,
                           mode | S_IFDIR, &ino);
    if (ret < 0)
        return VTFS_MKDIR_RET_ERR(ret);

    inode = vtfs_iget(dir->i_sb, ino, mode | S_IFDIR, 0, 2);
    if (IS_ERR(inode))
        return VTFS_MKDIR_RET_ERR(PTR_ERR(inode));

    inc_nlink(dir);
    vtfs_update_time(dir);
    d_instantiate(dentry, inode);
    return VTFS_MKDIR_RET_OK;
}

static int vtfs_unlink(struct inode *dir, struct dentry *dentry)
{
    struct vtfs_sb_info *sbi = VTFS_SB(dir->i_sb);
    struct vtfs_inode_info *dir_vi = VTFS_I(dir);
    struct inode *inode = d_inode(dentry);
    int ret;

    if (sbi->readonly)
        return -EROFS;

    ret = vtfs_proto_unlink(sbi, dir_vi->backend_ino, dentry->d_name.name);
    if (ret < 0)
        return ret;

    drop_nlink(inode);
    vtfs_update_time(dir);
    return 0;
}

static int vtfs_rmdir(struct inode *dir, struct dentry *dentry)
{
    struct vtfs_sb_info *sbi = VTFS_SB(dir->i_sb);
    struct vtfs_inode_info *dir_vi = VTFS_I(dir);
    struct inode *inode = d_inode(dentry);
    int ret;

    if (sbi->readonly)
        return -EROFS;

    ret = vtfs_proto_rmdir(sbi, dir_vi->backend_ino, dentry->d_name.name);
    if (ret < 0)
        return ret;

    clear_nlink(inode);
    drop_nlink(dir);
    vtfs_update_time(dir);
    return 0;
}

static int vtfs_link(struct dentry *old_dentry, struct inode *dir,
                     struct dentry *new_dentry)
{
    struct vtfs_sb_info *sbi = VTFS_SB(dir->i_sb);
    struct inode *inode = d_inode(old_dentry);
    struct vtfs_inode_info *vi = VTFS_I(inode);
    struct vtfs_inode_info *dir_vi = VTFS_I(dir);
    int ret;

    if (sbi->readonly)
        return -EROFS;

    if (S_ISDIR(inode->i_mode))
        return -EPERM;

    ret = vtfs_proto_link(sbi, vi->backend_ino, dir_vi->backend_ino,
                          new_dentry->d_name.name);
    if (ret < 0)
        return ret;

    inc_nlink(inode);
    ihold(inode);
    vtfs_update_time(dir);
    d_instantiate(new_dentry, inode);
    return 0;
}

struct vtfs_readdir_ctx {
    struct dir_context *ctx;
    struct super_block *sb;
    int count;
    int error;
};

static int vtfs_readdir_callback(void *data, const char *name, u64 ino, umode_t mode)
{
    struct vtfs_readdir_ctx *rctx = data;
    unsigned int type;
    loff_t cur_pos;

    cur_pos = rctx->count + 2;
    
    if (cur_pos < rctx->ctx->pos) {
        rctx->count++;
        return 0;
    }

    if (S_ISDIR(mode))
        type = DT_DIR;
    else if (S_ISREG(mode))
        type = DT_REG;
    else
        type = DT_UNKNOWN;

    if (!dir_emit(rctx->ctx, name, strlen(name), ino, type)) {
        rctx->error = -ENOBUFS;
        return -1;
    }

    rctx->ctx->pos++;
    rctx->count++;
    return 0;
}

static int vtfs_iterate_shared(struct file *file, struct dir_context *ctx)
{
    struct inode *inode = file_inode(file);
    struct vtfs_sb_info *sbi = VTFS_SB(inode->i_sb);
    struct vtfs_inode_info *vi = VTFS_I(inode);
    struct vtfs_readdir_ctx rctx;
    int ret;

    if (ctx->pos == 0) {
        if (!dir_emit_dot(file, ctx))
            return 0;
        ctx->pos = 1;
    }
    
    if (ctx->pos == 1) {
        if (!dir_emit_dotdot(file, ctx))
            return 0;
        ctx->pos = 2;
    }

    rctx.ctx = ctx;
    rctx.sb = inode->i_sb;
    rctx.count = 0;
    rctx.error = 0;

    ret = vtfs_proto_readdir(sbi, vi->backend_ino, vtfs_readdir_callback, &rctx);
    
    if (ret < 0 && ret != -ENOBUFS)
        return ret;
    
    if (rctx.error)
        return 0;

    return 0;
}

const struct inode_operations vtfs_dir_inode_ops = {
    .lookup = vtfs_lookup,
    .create = vtfs_create,
    .mkdir  = vtfs_mkdir,
    .unlink = vtfs_unlink,
    .rmdir  = vtfs_rmdir,
    .link   = vtfs_link,
};

const struct file_operations vtfs_dir_ops = {
    .owner          = THIS_MODULE,
    .llseek         = generic_file_llseek,
    .read           = generic_read_dir,
    VTFS_DIR_ITERATE = vtfs_iterate_shared,
};