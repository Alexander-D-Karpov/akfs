#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "vtfs.h"

static ssize_t vtfs_read(struct file *filp, char __user *buf,
                          size_t count, loff_t *ppos)
{
    struct inode *inode = file_inode(filp);
    struct vtfs_sb_info *sbi = VTFS_SB(inode->i_sb);
    struct vtfs_inode_info *vi = VTFS_I(inode);
    char *kbuf;
    ssize_t ret;
    loff_t size;

    size = i_size_read(inode);
    if (*ppos >= size)
        return 0;
    if (*ppos + count > size)
        count = size - *ppos;
    if (count == 0)
        return 0;

    kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    ret = vtfs_http_read(sbi, vi->backend_ino, kbuf, count, *ppos);
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

static ssize_t vtfs_write(struct file *filp, const char __user *buf,
                           size_t count, loff_t *ppos)
{
    struct inode *inode = file_inode(filp);
    struct vtfs_sb_info *sbi = VTFS_SB(inode->i_sb);
    struct vtfs_inode_info *vi = VTFS_I(inode);
    char *kbuf;
    ssize_t ret;
    loff_t new_size;

    if (sbi->readonly)
        return -EROFS;

    if (count == 0)
        return 0;

    if (count > VTFS_MAX_FILESIZE)
        count = VTFS_MAX_FILESIZE;

    kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, buf, count)) {
        kfree(kbuf);
        return -EFAULT;
    }

    ret = vtfs_http_write(sbi, vi->backend_ino, kbuf, count, *ppos, &new_size);
    if (ret < 0) {
        kfree(kbuf);
        return ret;
    }

    *ppos += ret;
    i_size_write(inode, new_size);
    inode->i_blocks = (new_size + 511) >> 9;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
    inode_set_mtime_to_ts(inode, inode_set_ctime_current(inode));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
    inode->i_mtime = inode_set_ctime_current(inode);
#else
    inode->i_mtime = inode->i_ctime = current_time(inode);
#endif

    kfree(kbuf);
    return ret;
}

static int vtfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    return 0;
}

static loff_t vtfs_llseek(struct file *file, loff_t offset, int whence)
{
    return generic_file_llseek(file, offset, whence);
}

const struct inode_operations vtfs_file_inode_ops = {
    .getattr = simple_getattr,
};

const struct file_operations vtfs_file_ops = {
    .owner  = THIS_MODULE,
    .read   = vtfs_read,
    .write  = vtfs_write,
    .llseek = vtfs_llseek,
    .fsync  = vtfs_fsync,
};