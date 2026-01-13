#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/unaligned.h>
#include <net/sock.h>
#include <linux/string.h>
#include <linux/errno.h>
#include "vtfs.h"

#define NET_TIMEOUT_SECS 30

int vtfs_net_connect(struct vtfs_sb_info *sbi)
{
    struct sockaddr_in addr;
    int ret;

    if (sbi->sock) {
        sock_release(sbi->sock);
        sbi->sock = NULL;
    }

    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sbi->sock);
    if (ret < 0) {
        VTFS_ERR("sock_create_kern failed: %d", ret);
        return ret;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(sbi->server_port);

    ret = in4_pton(sbi->server_host, -1, (u8 *)&addr.sin_addr.s_addr, -1, NULL);
    if (ret != 1) {
        VTFS_ERR("Invalid IP address: %s", sbi->server_host);
        sock_release(sbi->sock);
        sbi->sock = NULL;
        return -EINVAL;
    }

    sbi->sock->sk->sk_sndtimeo = NET_TIMEOUT_SECS * HZ;
    sbi->sock->sk->sk_rcvtimeo = NET_TIMEOUT_SECS * HZ;

    ret = kernel_connect(sbi->sock, (struct sockaddr *)&addr, sizeof(addr), 0);
    if (ret < 0) {
        VTFS_ERR("kernel_connect to %s:%d failed: %d", sbi->server_host, sbi->server_port, ret);
        sock_release(sbi->sock);
        sbi->sock = NULL;
        return ret;
    }

    VTFS_LOG("Connected to %s:%d", sbi->server_host, sbi->server_port);
    return 0;
}

void vtfs_net_disconnect(struct vtfs_sb_info *sbi)
{
    if (sbi->sock) {
        kernel_sock_shutdown(sbi->sock, SHUT_RDWR);
        sock_release(sbi->sock);
        sbi->sock = NULL;
    }
}

static int vtfs_net_roundtrip(struct vtfs_sb_info *sbi,
                              const u8 *req, int req_len,
                              u8 **out_resp, int *out_resp_len)
{
    struct vtfs_msg_header rhdr;
    u32 total_len, payload_len;
    u8 *resp;
    int ret;

    if (!sbi || !req || req_len < VTFS_HEADER_SIZE || !out_resp || !out_resp_len)
        return -EINVAL;

    *out_resp = NULL;
    *out_resp_len = 0;

    mutex_lock(&sbi->net_lock);

    ret = vtfs_net_send(sbi, (void *)req, (size_t)req_len);
    if (ret < 0)
        goto out_unlock;

    ret = vtfs_net_recv(sbi, &rhdr, VTFS_HEADER_SIZE);
    if (ret < 0)
        goto out_unlock;

    total_len = le32_to_cpu(rhdr.length);

    if (total_len < VTFS_HEADER_SIZE || total_len > VTFS_MAX_MSG) {
        ret = -EPROTO;
        goto out_unlock;
    }

    payload_len = total_len - VTFS_HEADER_SIZE;

    resp = kmalloc(total_len, GFP_KERNEL);
    if (!resp) {
        ret = -ENOMEM;
        goto out_unlock;
    }

    memcpy(resp, &rhdr, VTFS_HEADER_SIZE);

    if (payload_len) {
        ret = vtfs_net_recv(sbi, resp + VTFS_HEADER_SIZE, payload_len);
        if (ret < 0) {
            kfree(resp);
            goto out_unlock;
        }
    }

    *out_resp = resp;
    *out_resp_len = (int)total_len;
    ret = 0;

out_unlock:
    mutex_unlock(&sbi->net_lock);
    return ret;
}

int vtfs_net_init(struct vtfs_sb_info *sbi)
{
    struct vtfs_msg_header hdr;
    u8 *buf = NULL;
    u8 *resp = NULL;
    int buf_len, resp_len;
    u16 tok_len = 0;
    u8 *p;
    s32 err;
    u32 srv_ver, srv_max;
    int ret;

    if (!sbi)
        return -EINVAL;

    if (sbi->token[0] != '\0')
        tok_len = (u16)strnlen(sbi->token, VTFS_TOKEN_MAX - 1);

    buf_len = VTFS_HEADER_SIZE + 10 + tok_len;

    buf = kmalloc(buf_len, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    memset(&hdr, 0, sizeof(hdr));
    hdr.length  = cpu_to_le32((u32)buf_len);
    hdr.opcode  = cpu_to_le16(VTFS_OP_INIT);
    hdr.flags   = cpu_to_le16(0);
    hdr.txn_id  = cpu_to_le64(++sbi->txn_counter);
    hdr.node_id = cpu_to_le64(0);

    memcpy(buf, &hdr, VTFS_HEADER_SIZE);

    p = buf + VTFS_HEADER_SIZE;
    put_unaligned_le32(VTFS_PROTO_VERSION, p + 0);
    put_unaligned_le32(VTFS_MAX_MSG,       p + 4);
    put_unaligned_le16(tok_len,            p + 8);
    if (tok_len)
        memcpy(p + 10, sbi->token, tok_len);

    ret = vtfs_net_roundtrip(sbi, buf, buf_len, &resp, &resp_len);
    if (ret < 0)
        goto out;

    if (resp_len < VTFS_HEADER_SIZE + 12) {
        ret = -EPROTO;
        goto out;
    }

    {
        struct vtfs_msg_header *rh = (struct vtfs_msg_header *)resp;
        u16 rop   = le16_to_cpu(rh->opcode);
        u16 rflag = le16_to_cpu(rh->flags);

        if (rop != VTFS_OP_INIT || !(rflag & VTFS_FLAG_RESPONSE)) {
            ret = -EPROTO;
            goto out;
        }
    }

    err = (s32)get_unaligned_le32(resp + VTFS_HEADER_SIZE + 0);
    srv_ver = get_unaligned_le32(resp + VTFS_HEADER_SIZE + 4);
    srv_max = get_unaligned_le32(resp + VTFS_HEADER_SIZE + 8);

    if (err) {
        ret = err;
        goto out;
    }

    if (srv_ver != VTFS_PROTO_VERSION) {
        VTFS_ERR("Protocol version mismatch: server=%u client=%u", srv_ver, (u32)VTFS_PROTO_VERSION);
        ret = -EPROTO;
        goto out;
    }

    VTFS_LOG("INIT ok: server_ver=%u server_max=%u", srv_ver, srv_max);
    ret = 0;

out:
    kfree(buf);
    kfree(resp);
    return ret;
}



int vtfs_net_send(struct vtfs_sb_info *sbi, void *buf, size_t len)
{
    struct msghdr msg = {0};
    struct kvec iov;
    int ret;
    size_t sent = 0;

    if (!sbi->sock) {
        ret = vtfs_net_connect(sbi);
        if (ret < 0)
            return ret;
    }

    while (sent < len) {
        iov.iov_base = (char *)buf + sent;
        iov.iov_len = len - sent;

        ret = kernel_sendmsg(sbi->sock, &msg, &iov, 1, iov.iov_len);
        if (ret < 0) {
            VTFS_ERR("kernel_sendmsg failed: %d", ret);
            vtfs_net_disconnect(sbi);
            return ret;
        }
        if (ret == 0) {
            VTFS_ERR("kernel_sendmsg returned 0");
            vtfs_net_disconnect(sbi);
            return -EIO;
        }
        sent += ret;
    }

    return 0;
}

int vtfs_net_recv(struct vtfs_sb_info *sbi, void *buf, size_t len)
{
    struct msghdr msg = {0};
    struct kvec iov;
    int ret;
    size_t received = 0;

    if (!sbi->sock)
        return -ENOTCONN;

    while (received < len) {
        iov.iov_base = (char *)buf + received;
        iov.iov_len = len - received;

        ret = kernel_recvmsg(sbi->sock, &msg, &iov, 1, iov.iov_len, 0);
        if (ret < 0) {
            VTFS_ERR("kernel_recvmsg failed: %d", ret);
            vtfs_net_disconnect(sbi);
            return ret;
        }
        if (ret == 0) {
            VTFS_ERR("Connection closed by server");
            vtfs_net_disconnect(sbi);
            return -ECONNRESET;
        }
        received += ret;
    }

    return 0;
}
