
/*
 * Copyright (C) Dmitry Volyntsev
 * Copyright (C) NGINX, Inc.
 */


#ifndef _NGX_SHA2_H_INCLUDED_
#define _NGX_SHA2_H_INCLUDED_


typedef struct {
    uint64_t  bytes;
    uint32_t  a, b, c, d, e, f, g, h;
    u_char    buffer[64];
} ngx_sha2_t;


void ngx_sha2_init(ngx_sha2_t *ctx);
void ngx_sha2_update(ngx_sha2_t *ctx, const void *data, size_t size);
void ngx_sha2_final(u_char result[32], ngx_sha2_t *ctx);


#endif /* _NGX_SHA2_H_INCLUDED_ */
