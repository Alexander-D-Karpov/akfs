#ifndef _VTFS_HTTP_H
#define _VTFS_HTTP_H

#include <linux/types.h>

#define HTTP_BUFFER_SIZE 65536
#define HTTP_MAX_URL_LEN 512

struct http_response {
    int status_code;
    char *body;
    size_t body_len;
};

int http_post_json(const char *url, const char *json_body,
                   struct http_response *response);
void http_response_free(struct http_response *response);

#endif