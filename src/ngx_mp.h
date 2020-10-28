
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) NGINX, Inc.
 */

#ifndef _NGX_MP_H_INCLUDED_
#define _NGX_MP_H_INCLUDED_


typedef struct ngx_mp_s  ngx_mp_t;

ngx_mp_t *ngx_mp_create(size_t cluster_size, size_t page_alignment,
    size_t page_size, size_t min_chunk_size);
void ngx_mp_destroy(ngx_mp_t *mp);
ngx_flag_t ngx_mp_is_empty(ngx_mp_t *mp);

void *ngx_mp_alloc(ngx_mp_t *mp, size_t size);
void *ngx_mp_zalloc(ngx_mp_t *mp, size_t size);
void *ngx_mp_align(ngx_mp_t *mp, size_t alignment, size_t size);
void *ngx_mp_zalign(ngx_mp_t *mp, size_t alignment, size_t size);
void ngx_mp_free(ngx_mp_t *mp, void *p);

void *ngx_mp_nget(ngx_mp_t *mp, size_t size);
void *ngx_mp_get(ngx_mp_t *mp, size_t size);
void *ngx_mp_zget(ngx_mp_t *mp, size_t size);


#endif /* _NGX_MP_H_INCLUDED_ */
