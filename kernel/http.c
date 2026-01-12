#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/inet.h>
#include <linux/delay.h>
#include <net/sock.h>
#include "http.h"
#include "vtfs.h"

#define HTTP_TIMEOUT_SECS 30

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_encode(const unsigned char *src, size_t src_len, char *dst, size_t dst_len)
{
    size_t i, j;
    size_t needed = ((src_len + 2) / 3) * 4 + 1;

    if (dst_len < needed)
        return 0;

    for (i = 0, j = 0; i < src_len; ) {
        uint32_t a = i < src_len ? src[i++] : 0;
        uint32_t b = i < src_len ? src[i++] : 0;
        uint32_t c = i < src_len ? src[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        dst[j++] = b64_table[(triple >> 18) & 0x3F];
        dst[j++] = b64_table[(triple >> 12) & 0x3F];
        dst[j++] = b64_table[(triple >> 6) & 0x3F];
        dst[j++] = b64_table[triple & 0x3F];
    }

    if (src_len % 3 >= 1)
        dst[j - 1] = '=';
    if (src_len % 3 == 1)
        dst[j - 2] = '=';

    dst[j] = '\0';
    return j;
}

static int b64_decode_char(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static size_t base64_decode(const char *src, size_t src_len, unsigned char *dst, size_t dst_len)
{
    size_t i, j;
    size_t pad = 0;
    size_t needed;

    if (src_len == 0 || src_len % 4 != 0)
        return 0;

    if (src[src_len - 1] == '=') pad++;
    if (src[src_len - 2] == '=') pad++;

    needed = (src_len / 4) * 3 - pad;
    if (dst_len < needed)
        return 0;

    for (i = 0, j = 0; i < src_len; ) {
        int a = b64_decode_char(src[i++]);
        int b = b64_decode_char(src[i++]);
        int c = src[i] == '=' ? 0 : b64_decode_char(src[i]); i++;
        int d = src[i] == '=' ? 0 : b64_decode_char(src[i]); i++;

        if (a < 0 || b < 0 || c < 0 || d < 0)
            return 0;

        uint32_t triple = (a << 18) | (b << 12) | (c << 6) | d;

        if (j < needed) dst[j++] = (triple >> 16) & 0xFF;
        if (j < needed) dst[j++] = (triple >> 8) & 0xFF;
        if (j < needed) dst[j++] = triple & 0xFF;
    }

    return needed;
}

static int parse_url(const char *url, char *host, int *port, char *path)
{
    const char *p = url;
    const char *host_start;
    const char *port_start;
    const char *path_start;
    int host_len;

    if (strncmp(p, "http://", 7) == 0)
        p += 7;
    else if (strncmp(p, "https://", 8) == 0)
        p += 8;

    host_start = p;
    port_start = strchr(p, ':');
    path_start = strchr(p, '/');

    if (port_start && (!path_start || port_start < path_start)) {
        host_len = port_start - host_start;
        if (host_len >= 128)
            host_len = 127;
        memcpy(host, host_start, host_len);
        host[host_len] = '\0';

        if (path_start) {
            char port_str[8] = {0};
            int port_len = path_start - port_start - 1;
            if (port_len > 7)
                port_len = 7;
            memcpy(port_str, port_start + 1, port_len);
            if (kstrtoint(port_str, 10, port) != 0)
                *port = 80;
        } else {
            if (kstrtoint(port_start + 1, 10, port) != 0)
                *port = 80;
        }
    } else {
        if (path_start)
            host_len = path_start - host_start;
        else
            host_len = strlen(host_start);

        if (host_len >= 128)
            host_len = 127;
        memcpy(host, host_start, host_len);
        host[host_len] = '\0';
        *port = 80;
    }

    if (path_start)
        strscpy(path, path_start, 256);
    else
        strcpy(path, "/");

    if (strcmp(host, "localhost") == 0)
        strcpy(host, "127.0.0.1");

    return 0;
}

static int tcp_connect(const char *host, int port, struct socket **sock)
{
    struct sockaddr_in addr;
    int ret;

    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, sock);
    if (ret < 0) {
        VTFS_ERR("sock_create_kern failed: %d", ret);
        return ret;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    ret = in4_pton(host, -1, (u8 *)&addr.sin_addr.s_addr, -1, NULL);
    if (ret != 1) {
        VTFS_ERR("Invalid IP address: %s", host);
        sock_release(*sock);
        *sock = NULL;
        return -EINVAL;
    }

    (*sock)->sk->sk_sndtimeo = HTTP_TIMEOUT_SECS * HZ;
    (*sock)->sk->sk_rcvtimeo = HTTP_TIMEOUT_SECS * HZ;

    ret = kernel_connect(*sock, (struct sockaddr *)&addr, sizeof(addr), 0);
    if (ret < 0) {
        VTFS_ERR("kernel_connect to %s:%d failed: %d", host, port, ret);
        sock_release(*sock);
        *sock = NULL;
        return ret;
    }

    return 0;
}

static int tcp_send_all(struct socket *sock, const char *data, size_t len)
{
    struct msghdr msg = {0};
    struct kvec iov;
    int ret;
    size_t sent = 0;

    while (sent < len) {
        iov.iov_base = (void *)(data + sent);
        iov.iov_len = len - sent;

        ret = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
        if (ret < 0) {
            VTFS_ERR("kernel_sendmsg failed: %d", ret);
            return ret;
        }
        if (ret == 0) {
            VTFS_ERR("kernel_sendmsg returned 0");
            return -EIO;
        }
        sent += ret;
    }
    return (int)sent;
}

static int tcp_recv_response(struct socket *sock, char *buf, size_t maxlen)
{
    struct msghdr msg = {0};
    struct kvec iov;
    int ret;
    size_t total = 0;
    int content_length = -1;
    char *header_end = NULL;
    char *cl_ptr;

    memset(buf, 0, maxlen);

    while (total < maxlen - 1) {
        iov.iov_base = buf + total;
        iov.iov_len = maxlen - 1 - total;

        ret = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);
        if (ret < 0) {
            if (ret == -EAGAIN || ret == -ETIMEDOUT) {
                if (total > 0 && header_end)
                    break;
                VTFS_ERR("recv timeout, total=%zu", total);
                return ret;
            }
            VTFS_ERR("kernel_recvmsg failed: %d", ret);
            return ret;
        }
        if (ret == 0)
            break;

        total += ret;
        buf[total] = '\0';

        if (!header_end) {
            header_end = strstr(buf, "\r\n\r\n");
            if (header_end) {
                cl_ptr = strstr(buf, "Content-Length:");
                if (!cl_ptr)
                    cl_ptr = strstr(buf, "content-length:");
                if (cl_ptr) {
                    if (sscanf(cl_ptr + 15, " %d", &content_length) != 1)
                        content_length = -1;
                }
            }
        }

        if (header_end && content_length >= 0) {
            size_t header_size = (header_end + 4) - buf;
            size_t body_received = total - header_size;
            if ((int)body_received >= content_length)
                break;
        }
    }

    return (int)total;
}

static int http_post_json_with_token(const char *url, const char *json_body,
                                      const char *token, struct http_response *response)
{
    struct socket *sock = NULL;
    char host[128] = {0};
    char path[256] = {0};
    int port;
    char *request = NULL;
    char *recv_buf = NULL;
    int ret;
    int req_len;
    char *body_start;
    char token_header[300] = "";

    memset(response, 0, sizeof(*response));

    ret = parse_url(url, host, &port, path);
    if (ret < 0)
        return ret;

    ret = tcp_connect(host, port, &sock);
    if (ret < 0)
        return -EIO;

    request = kmalloc(HTTP_BUFFER_SIZE, GFP_KERNEL);
    if (!request) {
        ret = -ENOMEM;
        goto out;
    }

    if (token && strlen(token) > 0)
        snprintf(token_header, sizeof(token_header), "X-Auth-Token: %s\r\n", token);

    req_len = snprintf(request, HTTP_BUFFER_SIZE,
                       "POST %s HTTP/1.1\r\n"
                       "Host: %s:%d\r\n"
                       "Content-Type: application/json\r\n"
                       "Content-Length: %zu\r\n"
                       "%s"
                       "Connection: close\r\n"
                       "\r\n"
                       "%s",
                       path, host, port, strlen(json_body), token_header, json_body);

    if (req_len < 0 || req_len >= HTTP_BUFFER_SIZE) {
        VTFS_ERR("Request too large");
        ret = -EINVAL;
        goto out;
    }

    ret = tcp_send_all(sock, request, req_len);
    if (ret < 0)
        goto out;

    recv_buf = kzalloc(HTTP_BUFFER_SIZE, GFP_KERNEL);
    if (!recv_buf) {
        ret = -ENOMEM;
        goto out;
    }

    ret = tcp_recv_response(sock, recv_buf, HTTP_BUFFER_SIZE);
    if (ret < 0)
        goto out;

    if (ret < 12) {
        VTFS_ERR("Response too short: %d bytes", ret);
        ret = -EIO;
        goto out;
    }

    if (sscanf(recv_buf, "HTTP/1.%*d %d", &response->status_code) != 1) {
        VTFS_ERR("Failed to parse status from: %.50s", recv_buf);
        ret = -EIO;
        goto out;
    }

    body_start = strstr(recv_buf, "\r\n\r\n");
    if (!body_start) {
        VTFS_ERR("No body separator found");
        ret = -EIO;
        goto out;
    }
    body_start += 4;

    response->body_len = ret - (body_start - recv_buf);
    response->body = kmalloc(response->body_len + 1, GFP_KERNEL);
    if (!response->body) {
        ret = -ENOMEM;
        goto out;
    }

    memcpy(response->body, body_start, response->body_len);
    response->body[response->body_len] = '\0';
    ret = 0;

out:
    if (sock)
        sock_release(sock);
    kfree(request);
    kfree(recv_buf);
    return ret;
}

int http_post_json(const char *url, const char *json_body,
                   struct http_response *response)
{
    return http_post_json_with_token(url, json_body, NULL, response);
}

void http_response_free(struct http_response *response)
{
    if (response) {
        kfree(response->body);
        response->body = NULL;
        response->body_len = 0;
    }
}

static int json_find_key(const char *json, const char *key,
                         const char **value_start, size_t *value_len)
{
    char search[68];
    const char *pos, *end;

    snprintf(search, sizeof(search), "\"%s\":", key);
    pos = strstr(json, search);
    if (!pos)
        return -ENOENT;

    pos += strlen(search);
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r')
        pos++;

    if (*pos == '"') {
        pos++;
        end = pos;
        while (*end && *end != '"') {
            if (*end == '\\' && *(end + 1))
                end++;
            end++;
        }
        *value_start = pos;
        *value_len = end - pos;
    } else {
        end = pos;
        while (*end && *end != ',' && *end != '}' && *end != ']' &&
               *end != ' ' && *end != '\t' && *end != '\n' && *end != '\r')
            end++;
        *value_start = pos;
        *value_len = end - pos;
    }

    return 0;
}

static int parse_json_int64(const char *json, const char *key, s64 *value)
{
    const char *val_start;
    size_t val_len;
    char buf[32];
    int ret;

    ret = json_find_key(json, key, &val_start, &val_len);
    if (ret < 0)
        return ret;

    if (val_len >= sizeof(buf))
        return -EINVAL;

    memcpy(buf, val_start, val_len);
    buf[val_len] = '\0';

    ret = kstrtoll(buf, 10, value);
    return ret;
}

static int parse_json_string(const char *json, const char *key,
                             char *buf, size_t buflen)
{
    const char *val_start;
    size_t val_len;
    int ret;

    ret = json_find_key(json, key, &val_start, &val_len);
    if (ret < 0)
        return ret;

    if (val_len >= buflen)
        val_len = buflen - 1;

    memcpy(buf, val_start, val_len);
    buf[val_len] = '\0';

    return 0;
}

int vtfs_http_lookup(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name,
                     u64 *out_ino, umode_t *out_mode, loff_t *out_size,
                     unsigned int *out_nlink)
{
    char url[HTTP_MAX_URL_LEN];
    char *json;
    struct http_response response;
    int ret;
    s64 ino, mode, size, nlink;

    if (strchr(name, '"') || strchr(name, '\\'))
        return -EINVAL;

    json = kmalloc(512, GFP_KERNEL);
    if (!json)
        return -ENOMEM;

    snprintf(url, sizeof(url), "%s/api/v1/lookup", sbi->server_url);
    snprintf(json, 512, "{\"parent_ino\":%llu,\"name\":\"%s\"}",
             (unsigned long long)parent_ino, name);

    mutex_lock(&sbi->http_lock);
    ret = http_post_json_with_token(url, json, sbi->token, &response);
    mutex_unlock(&sbi->http_lock);

    kfree(json);

    if (ret < 0)
        return ret;

    if (response.status_code == 404) {
        http_response_free(&response);
        return -ENOENT;
    }

    if (response.status_code != 200) {
        VTFS_ERR("lookup failed: HTTP %d", response.status_code);
        http_response_free(&response);
        return -EIO;
    }

    ret = parse_json_int64(response.body, "ino", &ino);
    if (ret < 0)
        goto out_free;

    ret = parse_json_int64(response.body, "mode", &mode);
    if (ret < 0)
        goto out_free;

    ret = parse_json_int64(response.body, "size", &size);
    if (ret < 0)
        goto out_free;

    ret = parse_json_int64(response.body, "nlink", &nlink);
    if (ret < 0)
        goto out_free;

    *out_ino = (u64)ino;
    *out_mode = (umode_t)mode;
    *out_size = (loff_t)size;
    *out_nlink = (unsigned int)nlink;
    ret = 0;

out_free:
    http_response_free(&response);
    return ret;
}

int vtfs_http_list(struct vtfs_sb_info *sbi, u64 parent_ino,
                   int (*callback)(void *ctx, const char *name, u64 ino, umode_t mode),
                   void *ctx)
{
    char url[HTTP_MAX_URL_LEN];
    char json[256];
    struct http_response response;
    int ret = 0;
    char *pos, *entry_start;
    char name[VTFS_NAME_MAX + 1];
    s64 ino, mode;

    snprintf(url, sizeof(url), "%s/api/v1/list", sbi->server_url);
    snprintf(json, sizeof(json), "{\"parent_ino\":%llu}",
             (unsigned long long)parent_ino);

    mutex_lock(&sbi->http_lock);
    ret = http_post_json_with_token(url, json, sbi->token, &response);
    mutex_unlock(&sbi->http_lock);

    if (ret < 0)
        return ret;

    if (response.status_code != 200) {
        http_response_free(&response);
        return -EIO;
    }

    pos = strstr(response.body, "\"entries\":");
    if (!pos) {
        http_response_free(&response);
        return 0;
    }

    pos = strchr(pos, '[');
    if (!pos) {
        http_response_free(&response);
        return 0;
    }

    while ((entry_start = strchr(pos, '{')) != NULL) {
        char *entry_end = strchr(entry_start, '}');
        if (!entry_end)
            break;

        if (parse_json_string(entry_start, "name", name, sizeof(name)) < 0)
            break;
        if (parse_json_int64(entry_start, "ino", &ino) < 0)
            break;
        if (parse_json_int64(entry_start, "mode", &mode) < 0)
            break;

        ret = callback(ctx, name, (u64)ino, (umode_t)mode);
        if (ret < 0)
            break;

        pos = entry_end + 1;
    }

    http_response_free(&response);
    return (ret == -ENOSPC) ? 0 : ret;
}

int vtfs_http_create(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name,
                     umode_t mode, u64 *out_ino)
{
    char url[HTTP_MAX_URL_LEN];
    char *json;
    struct http_response response;
    int ret;
    s64 ino;

    if (strchr(name, '"') || strchr(name, '\\'))
        return -EINVAL;

    json = kmalloc(512, GFP_KERNEL);
    if (!json)
        return -ENOMEM;

    snprintf(url, sizeof(url), "%s/api/v1/create", sbi->server_url);
    snprintf(json, 512, "{\"parent_ino\":%llu,\"name\":\"%s\",\"mode\":%u}",
             (unsigned long long)parent_ino, name, mode);

    mutex_lock(&sbi->http_lock);
    ret = http_post_json_with_token(url, json, sbi->token, &response);
    mutex_unlock(&sbi->http_lock);

    kfree(json);

    if (ret < 0)
        return ret;

    if (response.status_code == 409) {
        http_response_free(&response);
        return -EEXIST;
    }

    if (response.status_code == 507) {
        http_response_free(&response);
        return -ENOSPC;
    }

    if (response.status_code == 401 || response.status_code == 403) {
        http_response_free(&response);
        return -EACCES;
    }

    if (response.status_code != 200 && response.status_code != 201) {
        http_response_free(&response);
        return -EIO;
    }

    ret = parse_json_int64(response.body, "ino", &ino);
    if (ret == 0)
        *out_ino = (u64)ino;

    http_response_free(&response);
    return ret;
}

int vtfs_http_mkdir(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name,
                    umode_t mode, u64 *out_ino)
{
    char url[HTTP_MAX_URL_LEN];
    char *json;
    struct http_response response;
    int ret;
    s64 ino;

    if (strchr(name, '"') || strchr(name, '\\'))
        return -EINVAL;

    json = kmalloc(512, GFP_KERNEL);
    if (!json)
        return -ENOMEM;

    snprintf(url, sizeof(url), "%s/api/v1/mkdir", sbi->server_url);
    snprintf(json, 512, "{\"parent_ino\":%llu,\"name\":\"%s\",\"mode\":%u}",
             (unsigned long long)parent_ino, name, mode);

    mutex_lock(&sbi->http_lock);
    ret = http_post_json_with_token(url, json, sbi->token, &response);
    mutex_unlock(&sbi->http_lock);

    kfree(json);

    if (ret < 0)
        return ret;

    if (response.status_code == 409) {
        http_response_free(&response);
        return -EEXIST;
    }

    if (response.status_code == 401 || response.status_code == 403) {
        http_response_free(&response);
        return -EACCES;
    }

    if (response.status_code != 200 && response.status_code != 201) {
        http_response_free(&response);
        return -EIO;
    }

    ret = parse_json_int64(response.body, "ino", &ino);
    if (ret == 0)
        *out_ino = (u64)ino;

    http_response_free(&response);
    return ret;
}

int vtfs_http_unlink(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name)
{
    char url[HTTP_MAX_URL_LEN];
    char *json;
    struct http_response response;
    int ret;

    if (strchr(name, '"') || strchr(name, '\\'))
        return -EINVAL;

    json = kmalloc(512, GFP_KERNEL);
    if (!json)
        return -ENOMEM;

    snprintf(url, sizeof(url), "%s/api/v1/unlink", sbi->server_url);
    snprintf(json, 512, "{\"parent_ino\":%llu,\"name\":\"%s\"}",
             (unsigned long long)parent_ino, name);

    mutex_lock(&sbi->http_lock);
    ret = http_post_json_with_token(url, json, sbi->token, &response);
    mutex_unlock(&sbi->http_lock);

    kfree(json);

    if (ret < 0)
        return ret;

    if (response.status_code == 404) {
        http_response_free(&response);
        return -ENOENT;
    }

    if (response.status_code == 401 || response.status_code == 403) {
        http_response_free(&response);
        return -EACCES;
    }

    if (response.status_code == 400) {
        if (response.body && strstr(response.body, "EISDIR")) {
            http_response_free(&response);
            return -EISDIR;
        }
        http_response_free(&response);
        return -EINVAL;
    }

    if (response.status_code != 200) {
        http_response_free(&response);
        return -EIO;
    }

    http_response_free(&response);
    return 0;
}

int vtfs_http_rmdir(struct vtfs_sb_info *sbi, u64 parent_ino, const char *name)
{
    char url[HTTP_MAX_URL_LEN];
    char *json;
    struct http_response response;
    int ret;

    if (strchr(name, '"') || strchr(name, '\\'))
        return -EINVAL;

    json = kmalloc(512, GFP_KERNEL);
    if (!json)
        return -ENOMEM;

    snprintf(url, sizeof(url), "%s/api/v1/rmdir", sbi->server_url);
    snprintf(json, 512, "{\"parent_ino\":%llu,\"name\":\"%s\"}",
             (unsigned long long)parent_ino, name);

    mutex_lock(&sbi->http_lock);
    ret = http_post_json_with_token(url, json, sbi->token, &response);
    mutex_unlock(&sbi->http_lock);

    kfree(json);

    if (ret < 0)
        return ret;

    if (response.status_code == 404) {
        http_response_free(&response);
        return -ENOENT;
    }

    if (response.status_code == 401 || response.status_code == 403) {
        http_response_free(&response);
        return -EACCES;
    }

    if (response.status_code == 400) {
        if (response.body && strstr(response.body, "ENOTEMPTY")) {
            http_response_free(&response);
            return -ENOTEMPTY;
        }
        if (response.body && strstr(response.body, "ENOTDIR")) {
            http_response_free(&response);
            return -ENOTDIR;
        }
        http_response_free(&response);
        return -EINVAL;
    }

    if (response.status_code != 200) {
        http_response_free(&response);
        return -EIO;
    }

    http_response_free(&response);
    return 0;
}

int vtfs_http_link(struct vtfs_sb_info *sbi, u64 ino, u64 new_parent_ino,
                   const char *new_name)
{
    char url[HTTP_MAX_URL_LEN];
    char *json;
    struct http_response response;
    int ret;

    if (strchr(new_name, '"') || strchr(new_name, '\\'))
        return -EINVAL;

    json = kmalloc(512, GFP_KERNEL);
    if (!json)
        return -ENOMEM;

    snprintf(url, sizeof(url), "%s/api/v1/link", sbi->server_url);
    snprintf(json, 512, "{\"ino\":%llu,\"new_parent_ino\":%llu,\"new_name\":\"%s\"}",
             (unsigned long long)ino, (unsigned long long)new_parent_ino, new_name);

    mutex_lock(&sbi->http_lock);
    ret = http_post_json_with_token(url, json, sbi->token, &response);
    mutex_unlock(&sbi->http_lock);

    kfree(json);

    if (ret < 0)
        return ret;

    if (response.status_code == 404) {
        http_response_free(&response);
        return -ENOENT;
    }

    if (response.status_code == 409) {
        http_response_free(&response);
        return -EEXIST;
    }

    if (response.status_code == 401 || response.status_code == 403) {
        http_response_free(&response);
        return -EACCES;
    }

    if (response.status_code != 200) {
        http_response_free(&response);
        return -EIO;
    }

    http_response_free(&response);
    return 0;
}

ssize_t vtfs_http_read(struct vtfs_sb_info *sbi, u64 ino, char *buf,
                       size_t len, loff_t offset)
{
    char url[HTTP_MAX_URL_LEN];
    char json[256];
    struct http_response response;
    int ret;
    const char *data_start;
    size_t data_len;
    size_t decoded_len;

    snprintf(url, sizeof(url), "%s/api/v1/read", sbi->server_url);
    snprintf(json, sizeof(json), "{\"ino\":%llu,\"offset\":%lld,\"size\":%zu}",
             (unsigned long long)ino, (long long)offset, len);

    mutex_lock(&sbi->http_lock);
    ret = http_post_json_with_token(url, json, sbi->token, &response);
    mutex_unlock(&sbi->http_lock);

    if (ret < 0)
        return ret;

    if (response.status_code != 200) {
        http_response_free(&response);
        return -EIO;
    }

    ret = json_find_key(response.body, "data", &data_start, &data_len);
    if (ret < 0) {
        http_response_free(&response);
        return 0;
    }

    if (data_len == 0) {
        http_response_free(&response);
        return 0;
    }

    decoded_len = base64_decode(data_start, data_len, buf, len);

    http_response_free(&response);
    return decoded_len;
}

ssize_t vtfs_http_write(struct vtfs_sb_info *sbi, u64 ino, const char *buf,
                        size_t len, loff_t offset, loff_t *new_size)
{
    char url[HTTP_MAX_URL_LEN];
    char *json;
    char *b64_data;
    struct http_response response;
    int ret;
    s64 size;
    size_t b64_len;
    size_t json_size;

    b64_len = ((len + 2) / 3) * 4 + 1;
    b64_data = kmalloc(b64_len, GFP_KERNEL);
    if (!b64_data)
        return -ENOMEM;

    base64_encode(buf, len, b64_data, b64_len);

    json_size = 256 + b64_len;
    json = kmalloc(json_size, GFP_KERNEL);
    if (!json) {
        kfree(b64_data);
        return -ENOMEM;
    }

    snprintf(url, sizeof(url), "%s/api/v1/write", sbi->server_url);
    snprintf(json, json_size, "{\"ino\":%llu,\"offset\":%lld,\"data\":\"%s\"}",
             (unsigned long long)ino, (long long)offset, b64_data);

    kfree(b64_data);

    mutex_lock(&sbi->http_lock);
    ret = http_post_json_with_token(url, json, sbi->token, &response);
    mutex_unlock(&sbi->http_lock);

    kfree(json);

    if (ret < 0)
        return ret;

    if (response.status_code == 507) {
        http_response_free(&response);
        return -ENOSPC;
    }

    if (response.status_code == 401 || response.status_code == 403) {
        http_response_free(&response);
        return -EACCES;
    }

    if (response.status_code != 200) {
        http_response_free(&response);
        return -EIO;
    }

    ret = parse_json_int64(response.body, "new_size", &size);
    if (ret == 0 && new_size)
        *new_size = (loff_t)size;

    http_response_free(&response);
    return len;
}