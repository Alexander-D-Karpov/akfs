#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include "vtfs.h"

static int vtfs_wb_init(struct vtfs_write_buffer *wb, unsigned int max_pages)
{
    wb->pages = kvcalloc(max_pages, sizeof(struct page *), GFP_KERNEL);
    if (!wb->pages)
        return -ENOMEM;

    wb->nr_pages = 0;
    wb->max_pages = max_pages;
    wb->offset = 0;
    wb->len = 0;
    return 0;
}

static void vtfs_wb_free(struct vtfs_write_buffer *wb)
{
    unsigned int i;

    if (wb->pages) {
        for (i = 0; i < wb->nr_pages; i++) {
            if (wb->pages[i])
                __free_page(wb->pages[i]);
        }
        kvfree(wb->pages);
        wb->pages = NULL;
    }
    wb->nr_pages = 0;
    wb->len = 0;
}

static void vtfs_wb_reset(struct vtfs_write_buffer *wb)
{
    unsigned int i;

    for (i = 0; i < wb->nr_pages; i++) {
        if (wb->pages[i])
            __free_page(wb->pages[i]);
        wb->pages[i] = NULL;
    }
    wb->nr_pages = 0;
    wb->len = 0;
    wb->offset = 0;
}

static int vtfs_wb_append(struct vtfs_write_buffer *wb, const char __user *buf,
                          size_t len, loff_t pos)
{
    size_t copied = 0;

    if (wb->len == 0) {
        wb->offset = pos;
    } else if (pos != wb->offset + wb->len) {
        return -EAGAIN;
    }

    while (copied < len) {
        unsigned int page_idx;
        unsigned int page_off;
        unsigned int to_copy;
        struct page *page;
        void *kaddr;

        page_idx = wb->len / PAGE_SIZE;
        page_off = wb->len % PAGE_SIZE;

        if (page_idx >= wb->max_pages)
            return -EAGAIN;

        if (!wb->pages[page_idx]) {
            page = alloc_page(GFP_KERNEL | __GFP_ZERO);
            if (!page)
                return copied > 0 ? copied : -ENOMEM;
            wb->pages[page_idx] = page;
            if (page_idx >= wb->nr_pages)
                wb->nr_pages = page_idx + 1;
        }

        to_copy = min_t(size_t, PAGE_SIZE - page_off, len - copied);

        kaddr = kmap_local_page(wb->pages[page_idx]);
        if (copy_from_user(kaddr + page_off, buf + copied, to_copy)) {
            kunmap_local(kaddr);
            return copied > 0 ? copied : -EFAULT;
        }
        kunmap_local(kaddr);

        copied += to_copy;
        wb->len += to_copy;
    }

    return copied;
}

static int vtfs_do_flush(struct vtfs_file_handle *fh)
{
    struct vtfs_sb_info *sbi = fh->sbi;
    struct vtfs_inode_info *vi = VTFS_I(fh->inode);
    loff_t new_size;
    ssize_t ret;

    if (fh->wb.len == 0)
        return 0;

    ret = vtfs_proto_write_chunked(sbi, vi->backend_ino, &fh->wb, &new_size);
    if (ret < 0)
        return ret;

    fh->inode->i_size = new_size;
    fh->inode->i_blocks = (new_size + 511) >> 9;
    vi->cached_size = new_size;

    if (fh->ra_len > 0) {
        loff_t ra_end = fh->ra_offset + fh->ra_len;
        loff_t write_end = fh->wb.offset + fh->wb.len;
        if (fh->wb.offset < ra_end && write_end > fh->ra_offset)
            fh->ra_len = 0;
    }

    vtfs_wb_reset(&fh->wb);
    return 0;
}

static void vtfs_flush_work_fn(struct work_struct *work)
{
    struct vtfs_file_handle *fh = container_of(work, struct vtfs_file_handle, flush_work);
    unsigned long flags;
    int ret;

    spin_lock_irqsave(&fh->wb_lock, flags);
    if (fh->wb.len == 0) {
        fh->flush_pending = false;
        spin_unlock_irqrestore(&fh->wb_lock, flags);
        return;
    }
    spin_unlock_irqrestore(&fh->wb_lock, flags);

    ret = vtfs_do_flush(fh);

    spin_lock_irqsave(&fh->wb_lock, flags);
    fh->flush_error = ret;
    fh->flush_pending = false;
    spin_unlock_irqrestore(&fh->wb_lock, flags);
}

static int vtfs_flush_write_buffer(struct file *file)
{
    struct vtfs_file_handle *fh = file->private_data;
    unsigned long flags;
    int ret;

    if (!fh)
        return 0;

    spin_lock_irqsave(&fh->wb_lock, flags);
    if (fh->wb.len == 0) {
        spin_unlock_irqrestore(&fh->wb_lock, flags);
        return 0;
    }
    spin_unlock_irqrestore(&fh->wb_lock, flags);

    if (fh->flush_pending)
        flush_work(&fh->flush_work);

    ret = vtfs_do_flush(fh);
    return ret;
}

static void vtfs_schedule_flush(struct vtfs_file_handle *fh)
{
    unsigned long flags;

    spin_lock_irqsave(&fh->wb_lock, flags);
    if (!fh->flush_pending && fh->wb.len > 0) {
        fh->flush_pending = true;
        queue_work(fh->sbi->flush_wq, &fh->flush_work);
    }
    spin_unlock_irqrestore(&fh->wb_lock, flags);
}

static int vtfs_open(struct inode *inode, struct file *file)
{
    struct vtfs_sb_info *sbi = VTFS_SB(inode->i_sb);
    struct vtfs_inode_info *vi = VTFS_I(inode);
    struct vtfs_file_handle *fh;
    size_t ra_size;
    int ret;

    fh = kzalloc(sizeof(*fh), GFP_KERNEL);
    if (!fh)
        return -ENOMEM;

    ra_size = sbi->readahead_size;
    if (ra_size == 0)
        ra_size = VTFS_READAHEAD_SIZE;

    fh->ra_buf = kvmalloc(ra_size, GFP_KERNEL);
    if (!fh->ra_buf) {
        kfree(fh);
        return -ENOMEM;
    }

    ret = vtfs_wb_init(&fh->wb, VTFS_WRITE_PAGES_MAX);
    if (ret < 0) {
        kvfree(fh->ra_buf);
        kfree(fh);
        return ret;
    }

    spin_lock_init(&fh->wb_lock);
    INIT_WORK(&fh->flush_work, vtfs_flush_work_fn);

    fh->ra_offset = 0;
    fh->ra_len = 0;
    fh->backend_ino = vi->backend_ino;
    fh->sbi = sbi;
    fh->inode = inode;
    fh->flush_pending = false;
    fh->flush_error = 0;

    file->private_data = fh;
    return 0;
}

static int vtfs_release(struct inode *inode, struct file *file)
{
    struct vtfs_file_handle *fh = file->private_data;
    int ret = 0;

    if (fh) {
        if (fh->flush_pending)
            flush_work(&fh->flush_work);

        ret = vtfs_do_flush(fh);

        vtfs_wb_free(&fh->wb);
        kvfree(fh->ra_buf);
        kfree(fh);
    }
    file->private_data = NULL;

    return ret;
}

static ssize_t vtfs_read(struct file *file, char __user *buf, size_t len,
                         loff_t *ppos)
{
    struct inode *inode = file_inode(file);
    struct vtfs_sb_info *sbi = VTFS_SB(inode->i_sb);
    struct vtfs_file_handle *fh = file->private_data;
    size_t ra_size;
    loff_t pos = *ppos;
    ssize_t ret;
    size_t to_copy;

    if (fh && fh->wb.len > 0) {
        ret = vtfs_flush_write_buffer(file);
        if (ret < 0)
            return ret;
    }

    if (pos >= inode->i_size)
        return 0;

    if (pos + len > inode->i_size)
        len = inode->i_size - pos;

    if (len == 0)
        return 0;

    ra_size = sbi->readahead_size;
    if (ra_size == 0)
        ra_size = VTFS_READAHEAD_SIZE;

    if (fh && fh->ra_len > 0 &&
        pos >= fh->ra_offset &&
        pos < fh->ra_offset + (loff_t)fh->ra_len) {
        size_t buf_off = pos - fh->ra_offset;
        size_t avail = fh->ra_len - buf_off;

        to_copy = min(len, avail);

        if (copy_to_user(buf, fh->ra_buf + buf_off, to_copy))
            return -EFAULT;

        *ppos = pos + to_copy;
        return to_copy;
    }

    if (fh) {
        size_t fetch_size = max(len, ra_size);

        if (pos + fetch_size > inode->i_size)
            fetch_size = inode->i_size - pos;

        if (fetch_size > ra_size)
            fetch_size = ra_size;

        ret = vtfs_proto_read(sbi, fh->backend_ino, fh->ra_buf, fetch_size, pos);
        if (ret < 0)
            return ret;

        fh->ra_offset = pos;
        fh->ra_len = ret;

        to_copy = min(len, (size_t)ret);

        if (copy_to_user(buf, fh->ra_buf, to_copy))
            return -EFAULT;

        *ppos = pos + to_copy;
        return to_copy;
    }

    {
        struct vtfs_inode_info *vi = VTFS_I(inode);
        char *kbuf;

        kbuf = kvmalloc(len, GFP_KERNEL);
        if (!kbuf)
            return -ENOMEM;

        ret = vtfs_proto_read(sbi, vi->backend_ino, kbuf, len, pos);
        if (ret < 0) {
            kvfree(kbuf);
            return ret;
        }

        if (copy_to_user(buf, kbuf, ret)) {
            kvfree(kbuf);
            return -EFAULT;
        }

        *ppos = pos + ret;
        kvfree(kbuf);
        return ret;
    }
}

static ssize_t vtfs_write(struct file *file, const char __user *buf, size_t len,
                          loff_t *ppos)
{
    struct inode *inode = file_inode(file);
    struct vtfs_sb_info *sbi = VTFS_SB(inode->i_sb);
    struct vtfs_file_handle *fh = file->private_data;
    loff_t pos;
    int ret;
    ssize_t written;

    if (sbi->readonly)
        return -EROFS;

    if (len == 0)
        return 0;

    pos = *ppos;
    if (file->f_flags & O_APPEND)
        pos = i_size_read(inode);

    if (pos + len > VTFS_MAX_FILESIZE)
        return -EFBIG;

    if (!fh) {
        struct vtfs_inode_info *vi = VTFS_I(inode);
        char *kbuf;
        loff_t new_size;

        kbuf = kvmalloc(len, GFP_KERNEL);
        if (!kbuf)
            return -ENOMEM;

        if (copy_from_user(kbuf, buf, len)) {
            kvfree(kbuf);
            return -EFAULT;
        }

        written = vtfs_proto_write(sbi, vi->backend_ino, kbuf, len, pos, &new_size);
        kvfree(kbuf);

        if (written < 0)
            return written;

        *ppos = pos + written;
        inode->i_size = new_size;
        inode->i_blocks = (new_size + 511) >> 9;
        vi->cached_size = new_size;
        vtfs_update_time(inode);
        return written;
    }

    if (fh->flush_pending) {
        flush_work(&fh->flush_work);
        if (fh->flush_error) {
            ret = fh->flush_error;
            fh->flush_error = 0;
            return ret;
        }
    }

    if (fh->wb.len > 0) {
        loff_t wb_end = fh->wb.offset + fh->wb.len;
        bool contiguous = (pos == wb_end);
        bool fits = (fh->wb.len + len <= VTFS_WRITE_BUF_SIZE);

        if (!contiguous || !fits) {
            ret = vtfs_do_flush(fh);
            if (ret < 0)
                return ret;
        }
    }

    written = vtfs_wb_append(&fh->wb, buf, len, pos);
    if (written == -EAGAIN) {
        ret = vtfs_do_flush(fh);
        if (ret < 0)
            return ret;
        written = vtfs_wb_append(&fh->wb, buf, len, pos);
    }

    if (written < 0)
        return written;

    *ppos = pos + written;

    if (pos + written > inode->i_size) {
        inode->i_size = pos + written;
        inode->i_blocks = (inode->i_size + 511) >> 9;
        VTFS_I(inode)->cached_size = inode->i_size;
    }

    vtfs_update_time(inode);

    if (fh->wb.len >= VTFS_WRITE_BUF_SIZE / 2) {
        vtfs_schedule_flush(fh);
    }

    return written;
}

static int vtfs_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
    struct vtfs_file_handle *fh = file->private_data;

    if (fh && fh->flush_pending)
        flush_work(&fh->flush_work);

    return vtfs_flush_write_buffer(file);
}

static loff_t vtfs_llseek(struct file *file, loff_t offset, int whence)
{
    struct inode *inode = file_inode(file);
    struct vtfs_file_handle *fh = file->private_data;
    loff_t new_pos;
    int ret;

    if (fh && fh->wb.len > 0) {
        if (fh->flush_pending)
            flush_work(&fh->flush_work);
        ret = vtfs_do_flush(fh);
        if (ret < 0)
            return ret;
    }

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

    if (fh && new_pos < fh->ra_offset)
        fh->ra_len = 0;

    file->f_pos = new_pos;
    return new_pos;
}

const struct file_operations vtfs_file_ops = {
    .owner   = THIS_MODULE,
    .open    = vtfs_open,
    .release = vtfs_release,
    .llseek  = vtfs_llseek,
    .read    = vtfs_read,
    .write   = vtfs_write,
    .fsync   = vtfs_fsync,
};
