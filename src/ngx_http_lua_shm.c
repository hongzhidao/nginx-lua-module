
/*
 * Copyright (C) Jedo Hong
 */


#include <ngx_http_lua.h>


static int ngx_http_lua_shm_set(lua_State *L);
static int ngx_http_lua_shm_get(lua_State *L);
static int ngx_http_lua_shm_del(lua_State *L);
static int ngx_http_lua_shm_has(lua_State *L);
static int ngx_http_lua_shm_keys(lua_State *L);
static void ngx_http_lua_shm_expire(ngx_http_lua_shm_ctx_t *ctx, 
    ngx_uint_t n);
static void ngx_http_lua_shm_remove(ngx_http_lua_shm_ctx_t *ctx, 
    ngx_http_lua_shm_node_t *ln);


void
ngx_http_lua_register_shm(lua_State *L, ngx_http_lua_main_conf_t *lmcf)
{
    ngx_uint_t                   i;
    ngx_str_t                   *name;
    ngx_shm_zone_t             **zone;

    if (lmcf->shm_zones.nelts == 0) {
        lua_newtable(L);
        lua_setfield(L, -2, "shm");
    }

    lua_createtable(L, 0, lmcf->shm_zones.nelts);

    /* { __index = { get = ..., set = ... } } */
    lua_createtable(L, 0, 4);

    lua_createtable(L, 0, 10);

    lua_pushcfunction(L, ngx_http_lua_shm_set);
    lua_setfield(L, -2, "set");

    lua_pushcfunction(L, ngx_http_lua_shm_get);
    lua_setfield(L, -2, "get");

    lua_pushcfunction(L, ngx_http_lua_shm_del);
    lua_setfield(L, -2, "del");

    lua_pushcfunction(L, ngx_http_lua_shm_has);
    lua_setfield(L, -2, "has");

    lua_pushcfunction(L, ngx_http_lua_shm_keys);
    lua_setfield(L, -2, "keys");

    lua_setfield(L, -2, "__index");
    /* end of metatable */

    zone = lmcf->shm_zones.elts;

    for (i = 0; i < lmcf->shm_zones.nelts; i++) {
        name = &zone[i]->shm.name;
        lua_pushlstring(L, (char *) name->data, name->len);

        lua_createtable(L, 1, 0);
        lua_pushlightuserdata(L, zone[i]);
        ngx_http_lua_set_shm(L, -2);
        lua_pushvalue(L, -3);
        lua_setmetatable(L, -2);

        lua_rawset(L, -4);
    }

    lua_pop(L, 1);

    lua_setfield(L, -2, "shm");
}


static int
ngx_http_lua_shm_set(lua_State *L)
{
    int                        nargs;
    int                        value_type;
    u_char                     c;
    u_char                    *p;
    double                     num;
    size_t                     size;
    uint32_t                   hash;
    ngx_int_t                  rc;
    ngx_str_t                  key, value;
    lua_Integer                expired;
    ngx_shm_zone_t            *zone;
    ngx_rbtree_node_t         *node;
    ngx_http_request_t        *r;
    ngx_http_lua_shm_ctx_t    *ctx;
    ngx_http_lua_shm_node_t   *ln;
    ngx_http_lua_shm_table_t  *table;

    r = ngx_http_lua_get_request(L);

    nargs = lua_gettop(L);
    if (nargs != 3 && nargs != 4) {
        return luaL_error(L, "missing args");
    }    

    zone = ngx_http_lua_shm_get_zone(L, 1);
    ctx = zone->data;

    key.data = (u_char *) luaL_checklstring(L, 2, &key.len);

    hash = ngx_crc32_short(key.data, key.len);

    expired = 0;

    if (nargs == 4) {
        expired = luaL_checkinteger(L, 4);
        if (expired <= 0) {
            return luaL_error(L, "invalid expired time");
        }

        expired += expired * 1000 + ngx_current_msec;
    }

    value_type = lua_type(L, 3);

    switch (value_type) {

    case LUA_TSTRING:
        value.data = (u_char *) luaL_checklstring(L, 3, &value.len);
        break;

    case LUA_TNUMBER:
        num = lua_tonumber(L, 3);
        value.len = sizeof(double);
        value.data = (u_char *) &num;
        break;

    case LUA_TBOOLEAN:
        value.len = sizeof(u_char);
        c = lua_toboolean(L, 3) ? 1 : 0;
        value.data = &c;
        break;

    case LUA_TTABLE:
        break;

    default:
        return luaL_error(L, "invalid value type");
    }

    ngx_shmtx_lock(&ctx->shpool->mutex);

    ngx_http_lua_shm_expire(ctx, 1);

    rc = ngx_http_lua_shm_lookup(&ctx->sh->rbtree, hash, &key, &ln);

    if (rc != NGX_DECLINED) {
        ngx_http_lua_shm_remove(ctx, ln);
    }

    size = offsetof(ngx_rbtree_node_t, color)
           + offsetof(ngx_http_lua_shm_node_t, data)
           + key.len;

    if (value_type == LUA_TTABLE) {
        size += sizeof(ngx_http_lua_shm_table_t);

    } else {
        size += value.len;
    }

    node = ngx_slab_alloc_locked(ctx->shpool, size);

    if (node == NULL) {
        ngx_shmtx_unlock(&ctx->shpool->mutex);
        return luaL_error(L, "could not allocate node");
    }

    node->key = hash;

    ln = (ngx_http_lua_shm_node_t *) &node->color;

    ln->key_len = (u_short) key.len;
    p = ngx_copy(ln->data, key.data, key.len);

    if (value_type == LUA_TTABLE) {

        table = ngx_http_lua_shm_get_table_head(ln);

        rc = ngx_http_lua_shm_set_table(r, L, ctx, table, 3);

        if (rc != NGX_OK) {

            ngx_http_lua_shm_free_table(ctx, ln);
            ngx_slab_free_locked(ctx->shpool, node);

            ngx_shmtx_unlock(&ctx->shpool->mutex);

            return luaL_error(L, "invalid table value");
        }

    } else {
        ln->value_len = (uint32_t) value.len;
        ngx_memcpy(p, value.data, value.len);
    }

    ln->value_type = value_type;

    ln->expired = expired;

    ngx_rbtree_insert(&ctx->sh->rbtree, node);

    ngx_queue_insert_head(&ctx->sh->queue, &ln->queue);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 0;
}


static int
ngx_http_lua_shm_get(lua_State *L)
{
    int                        nargs;
    u_char                     c;
    double                     num;
    uint32_t                   hash;
    ngx_int_t                  rc;
    ngx_str_t                  key, value;
    ngx_shm_zone_t            *zone;
    ngx_http_lua_shm_ctx_t    *ctx;
    ngx_http_lua_shm_node_t   *ln;
    ngx_http_lua_shm_table_t  *table;

    nargs = lua_gettop(L);
    if (nargs < 2) {
        return luaL_error(L, "missing args");
    }    

    zone = ngx_http_lua_shm_get_zone(L, 1);
    ctx = zone->data;

    key.data = (u_char *) luaL_checklstring(L, 2, &key.len);

    hash = ngx_crc32_short(key.data, key.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_http_lua_shm_lookup(&ctx->sh->rbtree, hash, &key, &ln);

    if (rc != NGX_OK) {
        goto not_found;
    }

    if (nargs > 2) {
        table = ngx_http_lua_shm_get_table(L, ln, nargs - 1);        
        if (table == NULL) {
            goto not_found;
        }

        key.data = (u_char *) luaL_checklstring(L, nargs, &key.len);

        hash = ngx_crc32_short(key.data, key.len);

        rc = ngx_http_lua_shm_lookup(&table->rbtree, hash, &key, &ln);

        if (rc != NGX_OK) {
            goto not_found;
        }
    }

    value.data = ln->data + ln->key_len;
    value.len = (size_t) ln->value_len;

    switch (ln->value_type) {

    case LUA_TSTRING:
        lua_pushlstring(L, (const char *) value.data, value.len);
        break;

    case LUA_TNUMBER:
        ngx_memcpy(&num, value.data, sizeof(double));
        lua_pushnumber(L, num);
        break;

    case LUA_TBOOLEAN:
        c = *value.data;
        lua_pushboolean(L, c ? 1 : 0);
        break;

    default:
        goto not_found;
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 1;

not_found:

    lua_pushnil(L);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 1;
}


static int
ngx_http_lua_shm_del(lua_State *L)
{
    int                        nargs;
    uint32_t                   hash;
    ngx_int_t                  rc;
    ngx_str_t                  key;
    ngx_shm_zone_t            *zone;
    ngx_http_lua_shm_ctx_t    *ctx;
    ngx_http_lua_shm_node_t   *ln;

    nargs = lua_gettop(L);
    if (nargs != 2) {
        return luaL_error(L, "missing args");
    }    

    zone = ngx_http_lua_shm_get_zone(L, 1);
    ctx = zone->data;

    key.data = (u_char *) luaL_checklstring(L, 2, &key.len);

    hash = ngx_crc32_short(key.data, key.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_http_lua_shm_lookup(&ctx->sh->rbtree, hash, &key, &ln);
    if (rc != NGX_DECLINED) {
        ngx_http_lua_shm_remove(ctx, ln);
    }

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 0;
}


static int
ngx_http_lua_shm_has(lua_State *L)
{
    int                        nargs;
    uint32_t                   hash;
    ngx_int_t                  rc;
    ngx_str_t                  key;
    ngx_shm_zone_t            *zone;
    ngx_http_lua_shm_ctx_t    *ctx;
    ngx_http_lua_shm_node_t   *ln;

    nargs = lua_gettop(L);
    if (nargs != 2) {
        return luaL_error(L, "missing args");
    }    

    zone = ngx_http_lua_shm_get_zone(L, 1);
    ctx = zone->data;

    key.data = (u_char *) luaL_checklstring(L, 2, &key.len);

    hash = ngx_crc32_short(key.data, key.len);

    ngx_shmtx_lock(&ctx->shpool->mutex);

    rc = ngx_http_lua_shm_lookup(&ctx->sh->rbtree, hash, &key, &ln);

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    lua_pushboolean(L, (rc == NGX_OK) ? 1 : 0);

    return 1;
}


static int
ngx_http_lua_shm_keys(lua_State *L)
{
    int                        nargs;
    uint32_t                   hash;
    ngx_int_t                  rc;
    ngx_str_t                  key;
    ngx_uint_t                 num;
    ngx_queue_t               *q, *queue;
    ngx_shm_zone_t            *zone;
    ngx_http_lua_shm_ctx_t    *ctx;
    ngx_http_lua_shm_node_t   *ln;
    ngx_http_lua_shm_table_t  *table;

    nargs = lua_gettop(L);

    zone = ngx_http_lua_shm_get_zone(L, 1);
    ctx = zone->data;

    ngx_shmtx_lock(&ctx->shpool->mutex);

    queue = &ctx->sh->queue;

    if (nargs > 1) {

        key.data = (u_char *) luaL_checklstring(L, 2, &key.len);

        hash = ngx_crc32_short(key.data, key.len);

        rc = ngx_http_lua_shm_lookup(&ctx->sh->rbtree, hash, &key, &ln);
        if (rc != NGX_OK) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            lua_pushnil(L);
            return 1;
        }

        table = ngx_http_lua_shm_get_table(L, ln, nargs);
        if (table == NULL) {
            ngx_shmtx_unlock(&ctx->shpool->mutex);
            lua_pushnil(L);
            return 1;
        }

        queue = &table->queue;
    }

    if (ngx_queue_empty(queue)) {
        lua_createtable(L, 0, 0);
        goto done;
    }

    num = 0;

    for (q = ngx_queue_head(queue);
         q != ngx_queue_sentinel(queue);
         q = ngx_queue_next(q))
    {
        ln = ngx_queue_data(q, ngx_http_lua_shm_node_t, queue);

        if (ln->expired == 0 || ln->expired > ngx_current_msec) {
            num++;
        }
    }

    lua_createtable(L, num, 0);

    num = 0;

    for (q = ngx_queue_head(queue);
         q != ngx_queue_sentinel(queue);
         q = ngx_queue_next(q))
    {
        ln = ngx_queue_data(q, ngx_http_lua_shm_node_t, queue);

        if (ln->expired == 0 || ln->expired > ngx_current_msec) {
            lua_pushlstring(L, (char *) ln->data, ln->key_len);
            lua_rawseti(L, -2, num);
            num++;
        }
    }

done:

    ngx_shmtx_unlock(&ctx->shpool->mutex);

    return 1;
}


void
ngx_http_lua_shm_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t          **p;
    ngx_http_lua_shm_node_t    *ln, *lnt;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            ln = (ngx_http_lua_shm_node_t *) &node->color;
            lnt = (ngx_http_lua_shm_node_t *) &temp->color;

            p = (ngx_memn2cmp(ln->data, lnt->data, ln->key_len, lnt->key_len) < 0)
                ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


ngx_int_t
ngx_http_lua_shm_lookup(ngx_rbtree_t *rbtree, uint32_t hash, ngx_str_t *key,
    ngx_http_lua_shm_node_t **lnp)
{
    ngx_int_t                   rc;
    ngx_rbtree_node_t          *node, *sentinel;
    ngx_http_lua_shm_node_t    *ln;

    node = rbtree->root;
    sentinel = rbtree->sentinel;

    while (node != sentinel) {

        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        ln = (ngx_http_lua_shm_node_t *) &node->color;

        rc = ngx_memn2cmp(key->data, ln->data, key->len, (size_t) ln->key_len);

        if (rc == 0) {
            *lnp = ln;

            if (ln->expired && ln->expired < ngx_current_msec) {
                return NGX_DONE;
            }

            return NGX_OK;
        }

        node = (rc < 0) ? node->left : node->right;
    }

    *lnp = NULL;

    return NGX_DECLINED;
}


static void
ngx_http_lua_shm_expire(ngx_http_lua_shm_ctx_t *ctx, ngx_uint_t n)
{
    ngx_msec_t                  now;
    ngx_queue_t                *q;
    ngx_http_lua_shm_node_t    *ln;

    now = ngx_current_msec;

    while (n < 3) {

        if (ngx_queue_empty(&ctx->sh->queue)) {
            return;
        }

        q = ngx_queue_last(&ctx->sh->queue);

        ln = ngx_queue_data(q, ngx_http_lua_shm_node_t, queue);

        if (ln->expired && ln->expired < now) {
            ngx_http_lua_shm_remove(ctx, ln);
        }

        n++;
    }
}


static void
ngx_http_lua_shm_remove(ngx_http_lua_shm_ctx_t *ctx, ngx_http_lua_shm_node_t *ln)
{
    ngx_rbtree_node_t          *node;

    if (ln->value_type == LUA_TTABLE) {
        ngx_http_lua_shm_free_table(ctx, ln);
    }

    ngx_queue_remove(&ln->queue);

    node = (ngx_rbtree_node_t *)
               ((u_char *) ln - offsetof(ngx_rbtree_node_t, color));

    ngx_rbtree_delete(&ctx->sh->rbtree, node);

    ngx_slab_free_locked(ctx->shpool, node);
}
