#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/unaligned.h>   /* put_unaligned_le32 / get_unaligned_le32 */
#include <net/sock.h>
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

int vtfs_net_init(struct vtfs_sb_info *sbi)
{
    int ret;
    struct vtfs_msg_header hdr, resp_hdr;
    u8 init_req[8];
    u8 init_resp[12];
    u8 *buf;
    size_t buf_len;
    u32 resp_len, payload_len;

    ret = vtfs_net_connect(sbi);
    if (ret < 0)
        return ret;

    /* init request: version=1, max_msg=VTFS_MAX_MSG */
    put_unaligned_le32(1, init_req);
    put_unaligned_le32(VTFS_MAX_MSG, init_req + 4);

    buf_len = VTFS_HEADER_SIZE + sizeof(init_req);
    buf = kmalloc(buf_len, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    hdr.length = cpu_to_le32(buf_len);
    hdr.opcode = cpu_to_le16(VTFS_OP_INIT);
    hdr.flags  = cpu_to_le16(0); /* requests are plaintext for now TODO */
    hdr.txn_id = cpu_to_le64(++sbi->txn_counter);
    hdr.node_id = cpu_to_le64(0);

    memcpy(buf, &hdr, VTFS_HEADER_SIZE);
    memcpy(buf + VTFS_HEADER_SIZE, init_req, sizeof(init_req));

    ret = vtfs_net_send(sbi, buf, buf_len);
    kfree(buf);
    if (ret < 0)
        return ret;

    /* read response header */
    ret = vtfs_net_recv(sbi, &resp_hdr, VTFS_HEADER_SIZE);
    if (ret < 0)
        return ret;

    resp_len = le32_to_cpu(resp_hdr.length);
    if (resp_len < VTFS_HEADER_SIZE)
        return -EIO;

    payload_len = resp_len - VTFS_HEADER_SIZE;
    if (payload_len > sizeof(init_resp))
        return -EOVERFLOW;

    memset(init_resp, 0, sizeof(init_resp));
    if (payload_len) {
        ret = vtfs_net_recv(sbi, init_resp, payload_len);
        if (ret < 0)
            return ret;
    }

    if (payload_len < 4)
        return -EIO;

    if (get_unaligned_le32(init_resp) != 0) {
        VTFS_ERR("Server init failed: %d", (int)get_unaligned_le32(init_resp));
        return -EIO;
    }

    if (payload_len >= 12)
        VTFS_LOG("Protocol initialized, version %u", get_unaligned_le32(init_resp + 4));
    else
        VTFS_LOG("Protocol initialized (short reply)");

    return 0;
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
