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
#include <linux/delay.h>
#include "vtfs.h"

#define NET_TIMEOUT_SECS 30
#define MAX_RECONNECT_ATTEMPTS 3
#define RECONNECT_DELAY_MS 500

static int vtfs_do_connect(struct vtfs_sb_info *sbi);
static int vtfs_reconnect(struct vtfs_sb_info *sbi);
static int vtfs_do_init(struct vtfs_sb_info *sbi);

int vtfs_resolve_hostname(const char *hostname, char *ip_buf, size_t ip_buf_len)
{
    __be32 addr;
    int ret;

    ret = in4_pton(hostname, -1, (u8 *)&addr, -1, NULL);
    if (ret == 1) {
        strncpy(ip_buf, hostname, ip_buf_len - 1);
        ip_buf[ip_buf_len - 1] = '\0';
        return 0;
    }

    VTFS_ERR("Cannot resolve hostname: %s (provide IP address instead)", hostname);
    return -EINVAL;
}

static int vtfs_do_connect(struct vtfs_sb_info *sbi)
{
    struct sockaddr_in addr;
    char resolved_ip[64];
    int ret;

    if (sbi->sock) {
        kernel_sock_shutdown(sbi->sock, SHUT_RDWR);
        sock_release(sbi->sock);
        sbi->sock = NULL;
    }

    ret = vtfs_resolve_hostname(sbi->server_host, resolved_ip, sizeof(resolved_ip));
    if (ret < 0)
        return ret;

    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sbi->sock);
    if (ret < 0) {
        VTFS_ERR("sock_create_kern failed: %d", ret);
        return ret;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(sbi->server_port);

    ret = in4_pton(resolved_ip, -1, (u8 *)&addr.sin_addr.s_addr, -1, NULL);
    if (ret != 1) {
        VTFS_ERR("Invalid IP address: %s", resolved_ip);
        sock_release(sbi->sock);
        sbi->sock = NULL;
        return -EINVAL;
    }

    sbi->sock->sk->sk_sndtimeo = NET_TIMEOUT_SECS * HZ;
    sbi->sock->sk->sk_rcvtimeo = NET_TIMEOUT_SECS * HZ;

    ret = kernel_connect(sbi->sock, (struct sockaddr *)&addr, sizeof(addr), 0);
    if (ret < 0) {
        VTFS_DBG("kernel_connect to %s:%d failed: %d", resolved_ip, sbi->server_port, ret);
        sock_release(sbi->sock);
        sbi->sock = NULL;
        return ret;
    }

    VTFS_LOG("Connected to %s:%d", sbi->server_host, sbi->server_port);
    return 0;
}

static int vtfs_do_init(struct vtfs_sb_info *sbi)
{
    struct vtfs_msg_header hdr;
    struct vtfs_msg_header rhdr;
    u8 *buf = NULL;
    u8 *resp = NULL;
    int buf_len;
    u16 tok_len = 0;
    u8 *p;
    s32 err;
    u32 srv_ver;
    u32 total_len, payload_len;
    int ret;

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

    ret = vtfs_net_send_raw(sbi, buf, buf_len);
    if (ret < 0)
        goto out;

    ret = vtfs_net_recv_raw(sbi, &rhdr, VTFS_HEADER_SIZE);
    if (ret < 0)
        goto out;

    total_len = le32_to_cpu(rhdr.length);
    if (total_len < VTFS_HEADER_SIZE + 12 || total_len > VTFS_MAX_MSG) {
        ret = -EPROTO;
        goto out;
    }

    payload_len = total_len - VTFS_HEADER_SIZE;
    resp = kmalloc(payload_len, GFP_KERNEL);
    if (!resp) {
        ret = -ENOMEM;
        goto out;
    }

    ret = vtfs_net_recv_raw(sbi, resp, payload_len);
    if (ret < 0)
        goto out;

    err = (s32)get_unaligned_le32(resp + 0);
    srv_ver = get_unaligned_le32(resp + 4);

    if (err) {
        VTFS_ERR("Server rejected INIT: %d", err);
        ret = err;
        goto out;
    }

    if (srv_ver != VTFS_PROTO_VERSION) {
        VTFS_ERR("Protocol version mismatch: server=%u client=%u", srv_ver, (u32)VTFS_PROTO_VERSION);
        ret = -EPROTO;
        goto out;
    }

    VTFS_LOG("INIT successful, protocol version %u", srv_ver);
    ret = 0;

out:
    kfree(buf);
    kfree(resp);
    return ret;
}

static int vtfs_reconnect(struct vtfs_sb_info *sbi)
{
    int attempt;
    int ret;

    for (attempt = 0; attempt < MAX_RECONNECT_ATTEMPTS; attempt++) {
        if (attempt > 0) {
            VTFS_LOG("Reconnect attempt %d/%d...", attempt + 1, MAX_RECONNECT_ATTEMPTS);
            msleep(RECONNECT_DELAY_MS * (1 << attempt));
        }

        ret = vtfs_do_connect(sbi);
        if (ret < 0)
            continue;

        ret = vtfs_do_init(sbi);
        if (ret == 0) {
            VTFS_LOG("Reconnected successfully");
            return 0;
        }

        if (sbi->sock) {
            kernel_sock_shutdown(sbi->sock, SHUT_RDWR);
            sock_release(sbi->sock);
            sbi->sock = NULL;
        }
    }

    VTFS_ERR("Failed to reconnect after %d attempts", MAX_RECONNECT_ATTEMPTS);
    return ret;
}

int vtfs_net_connect(struct vtfs_sb_info *sbi)
{
    return vtfs_do_connect(sbi);
}

void vtfs_net_disconnect(struct vtfs_sb_info *sbi)
{
    if (sbi->sock) {
        kernel_sock_shutdown(sbi->sock, SHUT_RDWR);
        sock_release(sbi->sock);
        sbi->sock = NULL;
    }
}

int vtfs_net_init(struct vtfs_sb_info *sbi)
{
    int ret;

    ret = vtfs_do_connect(sbi);
    if (ret < 0)
        return ret;

    ret = vtfs_do_init(sbi);
    if (ret < 0) {
        vtfs_net_disconnect(sbi);
        return ret;
    }

    return 0;
}

int vtfs_net_send_raw(struct vtfs_sb_info *sbi, void *buf, size_t len)
{
    struct msghdr msg = {0};
    struct kvec iov;
    int ret;
    size_t sent = 0;

    if (!sbi->sock)
        return -ENOTCONN;

    while (sent < len) {
        iov.iov_base = (char *)buf + sent;
        iov.iov_len = len - sent;

        ret = kernel_sendmsg(sbi->sock, &msg, &iov, 1, iov.iov_len);
        if (ret < 0)
            return ret;
        if (ret == 0)
            return -EIO;
        sent += ret;
    }

    return 0;
}

int vtfs_net_recv_raw(struct vtfs_sb_info *sbi, void *buf, size_t len)
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
        if (ret < 0)
            return ret;
        if (ret == 0)
            return -ECONNRESET;
        received += ret;
    }

    return 0;
}

int vtfs_net_send(struct vtfs_sb_info *sbi, void *buf, size_t len)
{
    int ret;
    int reconnected = 0;

retry:
    if (!sbi->sock) {
        if (reconnected)
            return -ENOTCONN;

        ret = vtfs_reconnect(sbi);
        if (ret < 0)
            return ret;
        reconnected = 1;
    }

    ret = vtfs_net_send_raw(sbi, buf, len);
    if (ret < 0) {
        VTFS_DBG("Send failed: %d, attempting reconnect", ret);
        vtfs_net_disconnect(sbi);

        if (!reconnected) {
            reconnected = 1;
            goto retry;
        }
        return ret;
    }

    return 0;
}

int vtfs_net_recv(struct vtfs_sb_info *sbi, void *buf, size_t len)
{
    int ret;

    if (!sbi->sock)
        return -ENOTCONN;

    ret = vtfs_net_recv_raw(sbi, buf, len);
    if (ret < 0) {
        VTFS_DBG("Recv failed: %d", ret);
        vtfs_net_disconnect(sbi);
        return ret;
    }

    return 0;
}
