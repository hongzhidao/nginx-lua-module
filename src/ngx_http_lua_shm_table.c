
/*
 * Copyright (C) Jedo Hong
 */


#include <ngx_http_lua.h>


ngx_int_t
ngx_http_lua_shm_set_table(ngx_http_request_t *r, lua_State *L, 
    ngx_http_lua_shm_ctx_t *ctx, ngx_http_lua_shm_table_t *table, int index)
{
    ngx_int_t                          rc;
    int                                value_type;
    u_char                            *p;
    uint32_t                           hash;
    ngx_int_t                          size;
    ngx_str_t                          key, value;
    ngx_rbtree_node_t                 *node;
    ngx_http_lua_shm_node_t           *ln;
    ngx_http_lua_shm_table_t          *parent;

    ngx_rbtree_init(&table->rbtree, &table->sentinel,
                    ngx_http_lua_shm_rbtree_insert_value);

    ngx_queue_init(&table->queue);

    lua_pushnil(L);

    while (lua_next(L, index) != 0) {

        if (lua_type(L, -2) != LUA_TSTRING) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "attempt to use a non-string key");
            return NGX_ERROR;
        }

        key.data = (u_char *) lua_tolstring(L, -2, &key.len);

        if (key.len == 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "empty key");
            return NGX_ERROR;
        }

        if (key.len > 65535) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "key too long");
            return NGX_ERROR;
        }

        hash = ngx_crc32_short(key.data, key.len);

        value_type = lua_type(L, -1);

        switch (value_type) {

        case LUA_TSTRING:
            value.data = (u_char *) lua_tolstring(L, -1, &value.len);
            break;

        case LUA_TTABLE:
            break;

        default:
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "attempt to use %s as query arg value",
                          luaL_typename(L, -1));
            return NGX_ERROR;
        }

        rc = ngx_http_lua_shm_lookup(&table->rbtree, hash, &key, &ln);
        if (rc == NGX_OK) {
            continue;
        }

        size = offsetof(ngx_rbtree_node_t, color)
               + offsetof(ngx_http_lua_shm_node_t, data)
               + key.len;

        if (value_type == LUA_TSTRING) {
            size += value.len;

        } else {
            size += sizeof(ngx_http_lua_shm_table_t);
        }

        node = ngx_slab_alloc_locked(ctx->shpool, size);
        if (node == NULL) {
            return NGX_ERROR;
        }

        ln = (ngx_http_lua_shm_node_t *) &node->color;

        node->key = hash;
        ln->key_len = (u_short) key.len;
        p = ngx_copy(ln->data, key.data, key.len);

        if (value_type == LUA_TSTRING) {
            ln->value_len = (uint32_t) value.len;
            ngx_memcpy(p, value.data, value.len);

        } else {
            parent = ngx_http_lua_shm_get_table_head(ln);
            rc = ngx_http_lua_shm_set_table(r, L, ctx, parent, -2);
            if (rc != NGX_OK) {
                ngx_http_lua_shm_free_table(ctx, ln);
                ngx_slab_free_locked(ctx->shpool, node);
                return NGX_ERROR;
            }
        }

        ln->value_type = value_type;;

        ngx_rbtree_insert(&table->rbtree, node);

        ngx_queue_insert_head(&table->queue, &ln->queue);

        lua_pop(L, 1);
    }

    return NGX_OK;
}


ngx_http_lua_shm_table_t *
ngx_http_lua_shm_get_table(lua_State *L, ngx_http_lua_shm_node_t *ln, int n)
{
    int                        i;
    uint32_t                   hash;
    ngx_int_t                  rc;
    ngx_str_t                  key;
    ngx_http_lua_shm_table_t  *table;

    if (ln->value_type != LUA_TTABLE) {
        return NULL;
    }

    table = ngx_http_lua_shm_get_table_head(ln);

    for (i = 3; i <= n; i++) {
        key.data = (u_char *) luaL_checklstring(L, i, &key.len);

        hash = ngx_crc32_short(key.data, key.len);

        rc = ngx_http_lua_shm_lookup(&table->rbtree, hash, &key, &ln);

        if (rc != NGX_OK || ln->value_type != LUA_TTABLE) {
            return NULL;
        }

        table = ngx_http_lua_shm_get_table_head(ln);
    }

    return table;
}


void
ngx_http_lua_shm_free_table(ngx_http_lua_shm_ctx_t *ctx,
    ngx_http_lua_shm_node_t *ln)
{
    ngx_rbtree_t                          *rbtree;
    ngx_rbtree_node_t                     *node, *root, *sentinel;
    ngx_http_lua_shm_table_t              *table;

    table = ngx_http_lua_shm_get_table_head(ln);

    rbtree = &table->rbtree;
    sentinel = rbtree->sentinel;

    for ( ;; ) {
        root = rbtree->root;

        if (root == sentinel) {
            return;
        }

        node = ngx_rbtree_min(root, sentinel);

        ln = (ngx_http_lua_shm_node_t *) &node->color;

        if (ln->value_type == LUA_TTABLE) {
            ngx_http_lua_shm_free_table(ctx, ln);
        }

        ngx_rbtree_delete(rbtree, node);
        ngx_slab_free_locked(ctx->shpool, node);
    }
}
