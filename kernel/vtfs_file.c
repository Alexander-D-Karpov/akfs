#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include "vtfs.h"

static ssize_t vtfs_read(struct file *file, char __user *buf, size_t len,
                         loff_t *ppos)
{
    struct inode *inode = file_inode(file);
    struct vtfs_sb_info *sbi = VTFS_SB(inode->i_sb);
    struct vtfs_inode_info *vi = VTFS_I(inode);
    char *kbuf;
    ssize_t ret;

    if (*ppos >= inode->i_size)
        return 0;

    if (*ppos + len > inode->i_size)
        len = inode->i_size - *ppos;

    if (len == 0)
        return 0;

    kbuf = kmalloc(len, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    ret = vtfs_proto_read(sbi, vi->backend_ino, kbuf, len, *ppos);
    if (ret < 0) {
        kfree(kbuf);
        return ret;
    }

    if (copy_to_user(buf, kbuf, ret)) {
        kfree(kbuf);
        return -EFAULT;
    }

    *ppos += ret;
    kfree(kbuf);
    return ret;
}

static ssize_t vtfs_write(struct file *file, const char __user *buf, size_t len,
                          loff_t *ppos)
{
    struct inode *inode = file_inode(file);
    struct vtfs_sb_info *sbi = VTFS_SB(inode->i_sb);
    struct vtfs_inode_info *vi = VTFS_I(inode);
    char *kbuf;
    ssize_t ret;
    loff_t new_size;
    loff_t pos;

    if (sbi->readonly)
        return -EROFS;

    if (len == 0)
        return 0;

    pos = *ppos;
    if (file->f_flags & O_APPEND)
        pos = i_size_read(inode);

    if (pos + len > VTFS_MAX_FILESIZE)
        return -EFBIG;

    kbuf = kmalloc(len, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, buf, len)) {
        kfree(kbuf);
        return -EFAULT;
    }

    ret = vtfs_proto_write(sbi, vi->backend_ino, kbuf, len, pos, &new_size);
    kfree(kbuf);

    if (ret < 0)
        return ret;

    *ppos = pos + ret;
    inode->i_size = new_size;
    inode->i_blocks = (new_size + 511) >> 9;
    vi->cached_size = new_size;
    vtfs_update_time(inode);

    return ret;
}

static int vtfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    return 0;
}

static loff_t vtfs_llseek(struct file *file, loff_t offset, int whence)
{
    struct inode *inode = file_inode(file);
    loff_t new_pos;

    switch (whence) {
    case SEEK_SET:
        new_pos = offset;
        break;
    case SEEK_CUR:
        new_pos = file->f_pos + offset;
        break;
    case SEEK_END:
        new_pos = inode->i_size + offset;
        break;
    default:
        return -EINVAL;
    }

    if (new_pos < 0)
        return -EINVAL;

    file->f_pos = new_pos;
    return new_pos;
}

const struct file_operations vtfs_file_ops = {
    .owner   = THIS_MODULE,
    .llseek  = vtfs_llseek,
    .read    = vtfs_read,
    .write   = vtfs_write,
    .fsync   = vtfs_fsync,
};
