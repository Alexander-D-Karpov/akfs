#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/unaligned.h>
#include "vtfs.h"

#define PROTO_BUF_SIZE 65536

static int vtfs_send_request(struct vtfs_sb_info *sbi, u16 opcode, u64 node_id,
                             const void *payload, size_t payload_len,
                             void *resp_payload, size_t *resp_len)
{
    struct vtfs_msg_header hdr, resp_hdr;
    u8 *buf;
    size_t buf_len;
    int ret;
    u32 resp_payload_len;

    buf_len = VTFS_HEADER_SIZE + payload_len;
    buf = kmalloc(buf_len, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    hdr.length = cpu_to_le32(buf_len);
    hdr.opcode = cpu_to_le16(opcode);
    hdr.flags = cpu_to_le16(0);
    hdr.txn_id = cpu_to_le64(++sbi->txn_counter);
    hdr.node_id = cpu_to_le64(node_id);

    memcpy(buf, &hdr, VTFS_HEADER_SIZE);
    if (payload_len > 0)
        memcpy(buf + VTFS_HEADER_SIZE, payload, payload_len);

    mutex_lock(&sbi->net_lock);

    ret = vtfs_net_send(sbi, buf, buf_len);
    if (ret < 0) {
        mutex_unlock(&sbi->net_lock);
        kfree(buf);
        return ret;
    }

    kfree(buf);

    ret = vtfs_net_recv(sbi, &resp_hdr, VTFS_HEADER_SIZE);
    if (ret < 0) {
        mutex_unlock(&sbi->net_lock);
        return ret;
    }

    resp_payload_len = le32_to_cpu(resp_hdr.length) - VTFS_HEADER_SIZE;
    if (resp_payload_len > 0 && resp_payload && resp_len) {
        if (resp_payload_len > *resp_len) {
            VTFS_ERR("Response too large: %u > %zu", resp_payload_len, *resp_len);
            mutex_unlock(&sbi->net_lock);
            return -EOVERFLOW;
        }

        ret = vtfs_net_recv(sbi, resp_payload, resp_payload_len);
        if (ret < 0) {
            mutex_unlock(&sbi->net_lock);
            return ret;
        }
        *resp_len = resp_payload_len;
    }

    mutex_unlock(&sbi->net_lock);
    return 0;
}

int vtfs_proto_lookup(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name,
                      u64 *out_ino, umode_t *out_mode, loff_t *out_size,
                      unsigned int *out_nlink)
{
    u8 req[2 + VTFS_NAME_MAX];
    u8 resp[52];
    size_t req_len, resp_len;
    int ret;
    int32_t err;

    req_len = strlen(name);
    if (req_len > VTFS_NAME_MAX)
        return -ENAMETOOLONG;

    put_unaligned_le16(req_len, req);
    memcpy(req + 2, name, req_len);
    req_len += 2;

    resp_len = sizeof(resp);
    ret = vtfs_send_request(sbi, VTFS_OP_LOOKUP, parent_ino, req, req_len, resp, &resp_len);
    if (ret < 0)
        return ret;

    if (resp_len < 4)
        return -EIO;

    err = (int32_t)get_unaligned_le32(resp);
    if (err != 0)
        return err;

    if (resp_len < 52)
        return -EIO;

    *out_ino = get_unaligned_le64(resp + 4);
    *out_mode = (umode_t)get_unaligned_le32(resp + 12);
    *out_nlink = get_unaligned_le32(resp + 16);
    *out_size = (loff_t)get_unaligned_le64(resp + 20);

    return 0;
}

int vtfs_proto_getattr(struct vtfs_sb_info *sbi, u64 ino, umode_t *out_mode,
                       loff_t *out_size, unsigned int *out_nlink)
{
    u8 resp[52];
    size_t resp_len;
    int ret;
    int32_t err;

    resp_len = sizeof(resp);
    ret = vtfs_send_request(sbi, VTFS_OP_GETATTR, ino, NULL, 0, resp, &resp_len);
    if (ret < 0)
        return ret;

    if (resp_len < 4)
        return -EIO;

    err = (int32_t)get_unaligned_le32(resp);
    if (err != 0)
        return err;

    if (resp_len < 52)
        return -EIO;

    *out_mode = (umode_t)get_unaligned_le32(resp + 12);
    *out_nlink = get_unaligned_le32(resp + 16);
    *out_size = (loff_t)get_unaligned_le64(resp + 20);

    return 0;
}

int vtfs_proto_readdir(struct vtfs_sb_info *sbi, u64 dir_ino,
                       int (*callback)(void *ctx, const char *name, u64 ino, umode_t mode),
                       void *ctx)
{
    u8 req[12];
    u8 *resp;
    size_t resp_len;
    int ret;
    int32_t err;
    u32 count, i;
    size_t off;

    put_unaligned_le64(0, req);
    put_unaligned_le32(1000, req + 8);

    resp = kmalloc(PROTO_BUF_SIZE, GFP_KERNEL);
    if (!resp)
        return -ENOMEM;

    resp_len = PROTO_BUF_SIZE;
    ret = vtfs_send_request(sbi, VTFS_OP_READDIR, dir_ino, req, sizeof(req), resp, &resp_len);
    if (ret < 0) {
        kfree(resp);
        return ret;
    }

    if (resp_len < 8) {
        kfree(resp);
        return -EIO;
    }

    err = (int32_t)get_unaligned_le32(resp);
    if (err != 0) {
        kfree(resp);
        return err;
    }

    count = get_unaligned_le32(resp + 4);
    off = 8;

    for (i = 0; i < count; i++) {
        u64 ino;
        u32 mode;
        u16 name_len;
        char name[VTFS_NAME_MAX + 1];

        if (off + 14 > resp_len)
            break;

        ino = get_unaligned_le64(resp + off);
        mode = get_unaligned_le32(resp + off + 8);
        name_len = get_unaligned_le16(resp + off + 12);

        if (off + 14 + name_len > resp_len)
            break;

        if (name_len > VTFS_NAME_MAX)
            name_len = VTFS_NAME_MAX;

        memcpy(name, resp + off + 14, name_len);
        name[name_len] = '\0';

        ret = callback(ctx, name, ino, mode);
        if (ret < 0)
            break;

        off += 14 + name_len;
    }

    kfree(resp);
    return 0;
}

int vtfs_proto_create(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name,
                      umode_t mode, u64 *out_ino)
{
    u8 req[6 + VTFS_NAME_MAX];
    u8 resp[52];
    size_t req_len, resp_len, name_len;
    int ret;
    int32_t err;

    name_len = strlen(name);
    if (name_len > VTFS_NAME_MAX)
        return -ENAMETOOLONG;

    put_unaligned_le32(mode, req);
    put_unaligned_le16(name_len, req + 4);
    memcpy(req + 6, name, name_len);
    req_len = 6 + name_len;

    resp_len = sizeof(resp);
    ret = vtfs_send_request(sbi, VTFS_OP_CREATE, parent_ino, req, req_len, resp, &resp_len);
    if (ret < 0)
        return ret;

    if (resp_len < 4)
        return -EIO;

    err = (int32_t)get_unaligned_le32(resp);
    if (err != 0)
        return err;

    if (resp_len < 12)
        return -EIO;

    *out_ino = get_unaligned_le64(resp + 4);
    return 0;
}

int vtfs_proto_mkdir(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name,
                     umode_t mode, u64 *out_ino)
{
    u8 req[6 + VTFS_NAME_MAX];
    u8 resp[52];
    size_t req_len, resp_len, name_len;
    int ret;
    int32_t err;

    name_len = strlen(name);
    if (name_len > VTFS_NAME_MAX)
        return -ENAMETOOLONG;

    put_unaligned_le32(mode, req);
    put_unaligned_le16(name_len, req + 4);
    memcpy(req + 6, name, name_len);
    req_len = 6 + name_len;

    resp_len = sizeof(resp);
    ret = vtfs_send_request(sbi, VTFS_OP_MKDIR, parent_ino, req, req_len, resp, &resp_len);
    if (ret < 0)
        return ret;

    if (resp_len < 4)
        return -EIO;

    err = (int32_t)get_unaligned_le32(resp);
    if (err != 0)
        return err;

    if (resp_len < 12)
        return -EIO;

    *out_ino = get_unaligned_le64(resp + 4);
    return 0;
}

int vtfs_proto_unlink(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name)
{
    u8 req[2 + VTFS_NAME_MAX];
    u8 resp[4];
    size_t req_len, resp_len, name_len;
    int ret;
    int32_t err;

    name_len = strlen(name);
    if (name_len > VTFS_NAME_MAX)
        return -ENAMETOOLONG;

    put_unaligned_le16(name_len, req);
    memcpy(req + 2, name, name_len);
    req_len = 2 + name_len;

    resp_len = sizeof(resp);
    ret = vtfs_send_request(sbi, VTFS_OP_UNLINK, parent_ino, req, req_len, resp, &resp_len);
    if (ret < 0)
        return ret;

    if (resp_len < 4)
        return -EIO;

    err = (int32_t)get_unaligned_le32(resp);
    return err;
}

int vtfs_proto_rmdir(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name)
{
    u8 req[2 + VTFS_NAME_MAX];
    u8 resp[4];
    size_t req_len, resp_len, name_len;
    int ret;
    int32_t err;

    name_len = strlen(name);
    if (name_len > VTFS_NAME_MAX)
        return -ENAMETOOLONG;

    put_unaligned_le16(name_len, req);
    memcpy(req + 2, name, name_len);
    req_len = 2 + name_len;

    resp_len = sizeof(resp);
    ret = vtfs_send_request(sbi, VTFS_OP_RMDIR, parent_ino, req, req_len, resp, &resp_len);
    if (ret < 0)
        return ret;

    if (resp_len < 4)
        return -EIO;

    err = (int32_t)get_unaligned_le32(resp);
    return err;
}

int vtfs_proto_link(struct vtfs_sb_info *sbi, u64 ino, u64 new_parent_ino,
                    const char *new_name)
{
    u8 req[10 + VTFS_NAME_MAX];
    u8 resp[4];
    size_t req_len, resp_len, name_len;
    int ret;
    int32_t err;

    name_len = strlen(new_name);
    if (name_len > VTFS_NAME_MAX)
        return -ENAMETOOLONG;

    put_unaligned_le64(new_parent_ino, req);
    put_unaligned_le16(name_len, req + 8);
    memcpy(req + 10, new_name, name_len);
    req_len = 10 + name_len;

    resp_len = sizeof(resp);
    ret = vtfs_send_request(sbi, VTFS_OP_LINK, ino, req, req_len, resp, &resp_len);
    if (ret < 0)
        return ret;

    if (resp_len < 4)
        return -EIO;

    err = (int32_t)get_unaligned_le32(resp);
    return err;
}

ssize_t vtfs_proto_read(struct vtfs_sb_info *sbi, u64 ino, char *buf,
                        size_t len, loff_t offset)
{
    u8 req[12];
    u8 *resp;
    size_t resp_len;
    int ret;
    int32_t err;
    u32 data_len;

    put_unaligned_le64(offset, req);
    put_unaligned_le32(len, req + 8);

    resp = kvmalloc(8 + len, GFP_KERNEL);
    if (!resp)
        return -ENOMEM;

    resp_len = 8 + len;
    ret = vtfs_send_request(sbi, VTFS_OP_READ, ino, req, sizeof(req), resp, &resp_len);
    if (ret < 0) {
        kvfree(resp);
        return ret;
    }

    if (resp_len < 8) {
        kvfree(resp);
        return -EIO;
    }

    err = (int32_t)get_unaligned_le32(resp);
    if (err != 0) {
        kvfree(resp);
        return err;
    }

    data_len = get_unaligned_le32(resp + 4);
    if (data_len > len)
        data_len = len;

    if (resp_len < 8 + data_len) {
        kvfree(resp);
        return -EIO;
    }

    memcpy(buf, resp + 8, data_len);
    kvfree(resp);
    return data_len;
}

ssize_t vtfs_proto_write(struct vtfs_sb_info *sbi, u64 ino, const char *buf,
                         size_t len, loff_t offset, loff_t *new_size)
{
    u8 *req;
    u8 resp[16];
    size_t req_len, resp_len;
    int ret;
    int32_t err;

    req_len = 12 + len;
    req = kvmalloc(req_len, GFP_KERNEL);
    if (!req)
        return -ENOMEM;

    put_unaligned_le64(offset, req);
    put_unaligned_le32(len, req + 8);
    memcpy(req + 12, buf, len);

    resp_len = sizeof(resp);
    ret = vtfs_send_request(sbi, VTFS_OP_WRITE, ino, req, req_len, resp, &resp_len);
    kvfree(req);

    if (ret < 0)
        return ret;

    if (resp_len < 4)
        return -EIO;

    err = (int32_t)get_unaligned_le32(resp);
    if (err != 0)
        return err;

    if (resp_len < 16)
        return -EIO;

    if (new_size)
        *new_size = (loff_t)get_unaligned_le64(resp + 8);

    return (ssize_t)get_unaligned_le32(resp + 4);
}

ssize_t vtfs_proto_write_chunked(struct vtfs_sb_info *sbi, u64 ino,
                                  struct vtfs_write_buffer *wb, loff_t *new_size)
{
    u8 *chunk_buf;
    size_t total_written = 0;
    loff_t current_offset;
    size_t remaining;
    int ret;

    if (wb->len == 0)
        return 0;

    chunk_buf = kvmalloc(VTFS_WRITE_CHUNK_SIZE, GFP_KERNEL);
    if (!chunk_buf)
        return -ENOMEM;

    current_offset = wb->offset;
    remaining = wb->len;

    while (remaining > 0) {
        size_t chunk_size = min_t(size_t, remaining, VTFS_WRITE_CHUNK_SIZE);
        size_t buf_offset = total_written;
        size_t copied = 0;
        loff_t chunk_new_size;
        ssize_t written;

        while (copied < chunk_size) {
            unsigned int page_idx = (buf_offset + copied) / PAGE_SIZE;
            unsigned int page_off = (buf_offset + copied) % PAGE_SIZE;
            unsigned int to_copy = min_t(size_t, PAGE_SIZE - page_off, chunk_size - copied);
            void *kaddr;

            if (page_idx >= wb->nr_pages || !wb->pages[page_idx])
                break;

            kaddr = kmap_local_page(wb->pages[page_idx]);
            memcpy(chunk_buf + copied, kaddr + page_off, to_copy);
            kunmap_local(kaddr);

            copied += to_copy;
        }

        if (copied == 0)
            break;

        written = vtfs_proto_write(sbi, ino, chunk_buf, copied,
                                   current_offset, &chunk_new_size);
        if (written < 0) {
            kvfree(chunk_buf);
            return written;
        }

        total_written += written;
        current_offset += written;
        remaining -= written;

        if (new_size)
            *new_size = chunk_new_size;

        if (written < copied)
            break;
    }

    kvfree(chunk_buf);
    return total_written;
}

int vtfs_proto_truncate(struct vtfs_sb_info *sbi, u64 ino, loff_t size)
{
    u8 req[8];
    u8 resp[4];
    size_t resp_len;
    int ret;
    int32_t err;

    put_unaligned_le64((u64)size, req);

    resp_len = sizeof(resp);
    ret = vtfs_send_request(sbi, VTFS_OP_TRUNCATE, ino,
                            req, sizeof(req),
                            resp, &resp_len);
    if (ret < 0)
        return ret;

    if (resp_len < 4)
        return -EIO;

    err = (int32_t)get_unaligned_le32(resp);
    return err;
}

int vtfs_proto_rename(struct vtfs_sb_info *sbi,
                      u64 old_parent_ino, const char *old_name,
                      u64 new_parent_ino, const char *new_name)
{
    u8 *req;
    u8 resp[4];
    size_t old_len, new_len;
    size_t req_len, resp_len;
    int ret;
    int32_t err;

    old_len = strlen(old_name);
    new_len = strlen(new_name);
    if (old_len > VTFS_NAME_MAX || new_len > VTFS_NAME_MAX)
        return -ENAMETOOLONG;

    req_len = 8 + 2 + old_len + 2 + new_len;
    req = kmalloc(req_len, GFP_KERNEL);
    if (!req)
        return -ENOMEM;

    put_unaligned_le64(new_parent_ino, req);

    put_unaligned_le16((u16)old_len, req + 8);
    memcpy(req + 10, old_name, old_len);

    put_unaligned_le16((u16)new_len, req + 10 + old_len);
    memcpy(req + 12 + old_len, new_name, new_len);

    resp_len = sizeof(resp);
    ret = vtfs_send_request(sbi, VTFS_OP_RENAME, old_parent_ino,
                            req, req_len, resp, &resp_len);
    kfree(req);

    if (ret < 0)
        return ret;

    if (resp_len < 4)
        return -EIO;

    err = (int32_t)get_unaligned_le32(resp);
    return err;
}
