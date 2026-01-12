#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "vtfs.h"

static struct dentry *vtfs_lookup(struct inode *dir, struct dentry *dentry,
                                   unsigned int flags)
{
    struct super_block *sb = dir->i_sb;
    struct vtfs_sb_info *sbi = VTFS_SB(sb);
    struct vtfs_inode_info *dir_vi = VTFS_I(dir);
    struct inode *inode = NULL;
    u64 child_ino;
    umode_t child_mode;
    loff_t child_size;
    unsigned int child_nlink;
    int ret;

    if (dentry->d_name.len > VTFS_NAME_MAX)
        return ERR_PTR(-ENAMETOOLONG);

    ret = vtfs_http_lookup(sbi, dir_vi->backend_ino, dentry->d_name.name,
                           &child_ino, &child_mode, &child_size, &child_nlink);

    if (ret == -ENOENT) {
        d_add(dentry, NULL);
        return NULL;
    }
    if (ret < 0)
        return ERR_PTR(ret);

    inode = vtfs_iget(sb, child_ino, child_mode, child_size, child_nlink);
    if (IS_ERR(inode))
        return ERR_CAST(inode);

    return d_splice_alias(inode, dentry);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int vtfs_create(struct mnt_idmap *idmap, struct inode *dir,
                       struct dentry *dentry, umode_t mode, bool excl)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static int vtfs_create(struct user_namespace *userns, struct inode *dir,
                       struct dentry *dentry, umode_t mode, bool excl)
#else
static int vtfs_create(struct inode *dir, struct dentry *dentry,
                       umode_t mode, bool excl)
#endif
{
    struct super_block *sb = dir->i_sb;
    struct vtfs_sb_info *sbi = VTFS_SB(sb);
    struct vtfs_inode_info *dir_vi = VTFS_I(dir);
    struct inode *inode;
    u64 new_ino;
    int ret;

    if (sbi->readonly)
        return -EROFS;

    ret = vtfs_http_create(sbi, dir_vi->backend_ino, dentry->d_name.name,
                           S_IFREG | mode, &new_ino);
    if (ret)
        return ret;

    inode = vtfs_iget(sb, new_ino, S_IFREG | mode, 0, 1);
    if (IS_ERR(inode))
        return PTR_ERR(inode);

    d_instantiate(dentry, inode);
    return 0;
}

static int vtfs_unlink(struct inode *dir, struct dentry *dentry)
{
    struct vtfs_sb_info *sbi = VTFS_SB(dir->i_sb);
    struct vtfs_inode_info *dir_vi = VTFS_I(dir);
    struct inode *inode = d_inode(dentry);
    int ret;

    if (sbi->readonly)
        return -EROFS;

    ret = vtfs_http_unlink(sbi, dir_vi->backend_ino, dentry->d_name.name);
    if (ret)
        return ret;

    drop_nlink(inode);
    return 0;
}

static int vtfs_link(struct dentry *old_dentry, struct inode *dir,
                     struct dentry *new_dentry)
{
    struct super_block *sb = dir->i_sb;
    struct vtfs_sb_info *sbi = VTFS_SB(sb);
    struct inode *inode = d_inode(old_dentry);
    struct vtfs_inode_info *vi = VTFS_I(inode);
    struct vtfs_inode_info *dir_vi = VTFS_I(dir);
    int ret;

    if (sbi->readonly)
        return -EROFS;

    if (S_ISDIR(inode->i_mode))
        return -EPERM;

    ret = vtfs_http_link(sbi, vi->backend_ino, dir_vi->backend_ino,
                         new_dentry->d_name.name);
    if (ret)
        return ret;

    inc_nlink(inode);
    ihold(inode);
    d_instantiate(new_dentry, inode);
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
static struct dentry *vtfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
                                  struct dentry *dentry, umode_t mode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
static int vtfs_mkdir(struct mnt_idmap *idmap, struct inode *dir,
                      struct dentry *dentry, umode_t mode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
static int vtfs_mkdir(struct user_namespace *userns, struct inode *dir,
                      struct dentry *dentry, umode_t mode)
#else
static int vtfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
#endif
{
    struct super_block *sb = dir->i_sb;
    struct vtfs_sb_info *sbi = VTFS_SB(sb);
    struct vtfs_inode_info *dir_vi = VTFS_I(dir);
    struct inode *inode;
    u64 new_ino;
    int ret;

    if (sbi->readonly)
        return VTFS_MKDIR_RET_ERR(-EROFS);

    ret = vtfs_http_mkdir(sbi, dir_vi->backend_ino, dentry->d_name.name,
                          S_IFDIR | mode, &new_ino);
    if (ret)
        return VTFS_MKDIR_RET_ERR(ret);

    inode = vtfs_iget(sb, new_ino, S_IFDIR | mode, 0, 2);
    if (IS_ERR(inode))
        return VTFS_MKDIR_RET_ERR(PTR_ERR(inode));

    inc_nlink(dir);
    d_instantiate(dentry, inode);
    return VTFS_MKDIR_RET_OK;
}

static int vtfs_rmdir(struct inode *dir, struct dentry *dentry)
{
    struct vtfs_sb_info *sbi = VTFS_SB(dir->i_sb);
    struct vtfs_inode_info *dir_vi = VTFS_I(dir);
    struct inode *inode = d_inode(dentry);
    int ret;

    if (sbi->readonly)
        return -EROFS;

    ret = vtfs_http_rmdir(sbi, dir_vi->backend_ino, dentry->d_name.name);
    if (ret)
        return ret;

    clear_nlink(inode);
    drop_nlink(dir);
    return 0;
}

struct vtfs_iterate_ctx {
    struct dir_context *ctx;
    struct super_block *sb;
    int index;
};

static int vtfs_iterate_callback(void *data, const char *name, u64 ino, umode_t mode)
{
    struct vtfs_iterate_ctx *iter_ctx = data;
    struct dir_context *ctx = iter_ctx->ctx;
    unsigned char d_type;

    if (iter_ctx->index + 2 < ctx->pos) {
        iter_ctx->index++;
        return 0;
    }

    if (S_ISDIR(mode))
        d_type = DT_DIR;
    else if (S_ISREG(mode))
        d_type = DT_REG;
    else
        d_type = DT_UNKNOWN;

    if (!dir_emit(ctx, name, strlen(name), ino, d_type))
        return -ENOSPC;

    ctx->pos++;
    iter_ctx->index++;
    return 0;
}

static int vtfs_iterate(struct file *file, struct dir_context *ctx)
{
    struct inode *inode = file_inode(file);
    struct vtfs_sb_info *sbi = VTFS_SB(inode->i_sb);
    struct vtfs_inode_info *vi = VTFS_I(inode);
    struct vtfs_iterate_ctx iter_ctx;
    int ret;

    if (!dir_emit_dots(file, ctx))
        return 0;

    iter_ctx.ctx = ctx;
    iter_ctx.sb = inode->i_sb;
    iter_ctx.index = 0;

    ret = vtfs_http_list(sbi, vi->backend_ino, vtfs_iterate_callback, &iter_ctx);
    if (ret < 0 && ret != -ENOSPC)
        return ret;

    return 0;
}

const struct inode_operations vtfs_dir_inode_ops = {
    .lookup     = vtfs_lookup,
    .create     = vtfs_create,
    .unlink     = vtfs_unlink,
    .link       = vtfs_link,
    .mkdir      = vtfs_mkdir,
    .rmdir      = vtfs_rmdir,
};

const struct file_operations vtfs_dir_ops = {
    .owner          = THIS_MODULE,
    .read           = generic_read_dir,
    VTFS_DIR_ITERATE = vtfs_iterate,
    .llseek         = generic_file_llseek,
};