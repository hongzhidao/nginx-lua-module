
/*
 * Copyright (C) Jedo Hong
 */


#include <ngx_http_lua.h>


static void ngx_http_lua_cleanup_state(void *data);
static void ngx_http_lua_cleanup_thread(void *data);


ngx_int_t
ngx_http_lua_init_state(ngx_conf_t *cf, ngx_http_lua_main_conf_t *lmcf)
{
    int                    status;
    u_char                *msg;
    u_char                *path;
    ngx_str_t             *file;
    lua_State             *L;
    ngx_pool_cleanup_t    *cln;

    if (lmcf->file.len == 0) {
        return NGX_DECLINED;
    } 

    L = luaL_newstate();
    if (L == NULL) {
        return NGX_ERROR;
    }

    luaL_openlibs(L);

    lua_createtable(L, 0, 100);

    ngx_http_lua_register_shm(L, lmcf);
    ngx_http_lua_register_meta(L);

    lua_setglobal(L, "ngx");

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    if (ngx_conf_full_name(cf->cycle, &lmcf->file, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    file = &lmcf->file;

    path = ngx_pcalloc(cf->pool, file->len + 1);
    if (path == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(path, file->data, file->len);
    *((char *) path + file->len) = '\0';

    status = luaL_loadfilex(L, (const char *) path, NULL);
    if (status != LUA_OK) {
        goto error;
    }

    if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
        goto error;
    }

    lmcf->state = L;

    cln->handler = ngx_http_lua_cleanup_state;
    cln->data = L;

    return NGX_OK;

error:

    msg = ngx_http_lua_get_error(L);

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", msg);

    return NGX_ERROR;
}


int
ngx_http_lua_get_index(lua_State *L)
{
    ngx_str_t  name;

    name.data = (u_char *) luaL_checklstring(L, -1, &name.len);

    ngx_http_lua_get_meta(L, -2);
    lua_getfield(L, -1, (const char *) name.data);

    if (!lua_isfunction(L, -1)) {
        lua_pushnil(L);
        return 1;
    }

    lua_call(L, 0, 1);

    return 1;
}


int
ngx_http_lua_set_index(lua_State *L)
{
    ngx_str_t  name;

    name.data = (u_char *) luaL_checklstring(L, -2, &name.len);

    ngx_http_lua_get_newmeta(L, -3);
    lua_getfield(L, -1, (const char *) name.data);

    if (!lua_isfunction(L, -1)) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushvalue(L, -3);
    lua_call(L, 1, 0);

    return 0;
}


static void
ngx_http_lua_cleanup_state(void *data)
{
    lua_State *L = data;

    lua_close(L);
}


static ngx_http_lua_ctx_t *
ngx_http_lua_get_ctx(ngx_http_request_t *r)
{
    ngx_http_lua_ctx_t       *ctx;
    ngx_pool_cleanup_t       *cln;
    ngx_http_lua_main_conf_t *lmcf;

    lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module);

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    if (ctx) {
        return ctx;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_lua_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_lua_module);

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    ctx->thread = lua_newthread(lmcf->state);
    if (ctx->thread == NULL) {
        return NULL;
    }

    ctx->ref = luaL_ref(lmcf->state, LUA_REGISTRYINDEX);

    cln->handler = ngx_http_lua_cleanup_thread;
    cln->data = r;

    ngx_http_lua_set_request(ctx->thread, r);

    return ctx;
}


static void
ngx_http_lua_cleanup_thread(void *data)
{
    ngx_http_request_t  *r = data;

    ngx_http_lua_ctx_t        *ctx;
    ngx_http_lua_main_conf_t  *lmcf;

    lmcf = ngx_http_cycle_get_module_main_conf(ngx_cycle, ngx_http_lua_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    luaL_unref(lmcf->state, LUA_REGISTRYINDEX, ctx->ref);
}


ngx_int_t 
ngx_http_lua_resume(ngx_http_request_t *r, ngx_str_t *name, ngx_event_t *wake)
{
    int                          status, nresults;
    u_char                      *msg;
    u_char                      *func;
    lua_State                   *state, *L;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_main_conf_t    *lmcf;

    lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module); 

    ctx = ngx_http_lua_get_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    if (ctx->wait) {
        return NGX_AGAIN;
    }

    state = lmcf->state;
    L = ctx->thread;

    if (ctx->wake) {
        goto resume;
    }

    ctx->wake = wake;

    func = ngx_pcalloc(r->pool, name->len + 1);
    if (func == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(func, name->data, name->len);
    *((char *) func + name->len) = '\0';

    lua_getglobal(state, (const char *) func);

    if (lua_type(state, -1) != LUA_TFUNCTION) {
        lua_pop(state, 1);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                      "can't find function: %s", func);
        return NGX_DECLINED;
    }

    lua_xmove(state, L, 1);

resume:

    status = lua_resume(L, NULL, 0, &nresults);

    if (status == LUA_YIELD) {
        return NGX_AGAIN;
    }

    ctx->wake = NULL;

    if (status == LUA_OK) {
        return ctx->status ? ctx->status : NGX_OK;
    }

    msg = ngx_http_lua_get_error(L);

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "lua exception: %s", msg);
    
    return NGX_ERROR;
}


ngx_int_t 
ngx_http_lua_eval(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *result)
{
    int                          status;
    u_char                      *func;
    lua_State                   *state, *L;
    ngx_event_t                 *wake;
    ngx_http_lua_ctx_t          *ctx;
    ngx_http_lua_main_conf_t    *lmcf;

    lmcf = ngx_http_get_module_main_conf(r, ngx_http_lua_module); 

    ctx = ngx_http_lua_get_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    state = lmcf->state;
    L = ctx->thread;

    func = ngx_pcalloc(r->pool, name->len + 1);
    if (func == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(func, name->data, name->len);
    *((char *) func + name->len) = '\0';

    lua_getglobal(state, (const char *) func);

    if (lua_type(state, -1) != LUA_TFUNCTION) {
        lua_pop(state, 1);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, 
                      "can't find function: %s", func);
        return NGX_DECLINED;
    }

    lua_xmove(state, L, 1);

    wake = ctx->wake;
    ctx->wake = NULL;

    status = lua_pcall(L, 0, 1, 0);

    ctx->wake = wake;

    if (status == LUA_OK) {
        if (result) {
            result->data = (u_char *) luaL_checklstring(L, -1, &result->len); 
        }
        return NGX_OK;
    }

    const char *msg = lua_tostring(L, -1);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "lua exception: %s", msg);
    
    return NGX_ERROR;
}


int
ngx_http_lua_yield(ngx_http_request_t *r)
{
    lua_State           *L;
    ngx_http_lua_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
    L = ctx->thread;

    if (ctx->wake) {
        ctx->wait = 1;
        return lua_yield(L, 0);
    }

    return luaL_error(L, "blocking calls are not allowed");
}


void
ngx_http_lua_wakeup(ngx_http_lua_ctx_t *ctx)
{
    ctx->wait = 0;
    ngx_post_event(ctx->wake, &ngx_posted_events);
}
