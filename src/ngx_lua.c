
/*
 * Copyright (C) hongzhidao
 */

#include <ngx_lua.h>


typedef struct {
    int                  handler;
    ngx_lua_ctx_t       *lua;
} ngx_lua_timer_t;


static void ngx_lua_log_register(lua_State *L);
static int ngx_lua_log(lua_State *L);
static int ngx_lua_base64_encode(lua_State *L);
static int ngx_lua_base64_decode(lua_State *L);
static int ngx_lua_timer(lua_State *L);


ngx_lua_ctx_t *
ngx_lua_create(lua_State *L, ngx_log_t *log)
{
    ngx_pool_t     *pool;
    ngx_lua_ctx_t  *lua;

    pool = ngx_create_pool(4096, log);
    if (pool == NULL) {
        return NULL;
    }

    lua = ngx_pcalloc(pool, sizeof(ngx_lua_ctx_t));
    if (lua == NULL) {
        return NULL;
    }

    lua->pool = pool;
    lua->main = L;

    lua->log = ngx_pcalloc(pool, sizeof(ngx_log_t));
    if (lua->log == NULL) {
        return NULL;
    }

    *lua->log = *log;

    lua->state = lua_newthread(L);
    if (lua->state == NULL) {
        return NULL;
    }
    
    lua->ref = luaL_ref(L, LUA_REGISTRYINDEX);

    ngx_lua_set_ext(lua->state, lua);

    return lua;
}


void
ngx_lua_destroy(ngx_lua_ctx_t *lua)
{
    ngx_destroy_pool(lua->pool);
    luaL_unref(lua->main, LUA_REGISTRYINDEX, lua->ref);
}


ngx_int_t 
ngx_lua_get_function(ngx_lua_ctx_t *lua, ngx_str_t *name)
{
    u_char     *func;
    lua_State  *L;

    L = lua->state;

    func = ngx_pcalloc(lua->pool, name->len + 1);
    if (func == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(func, name->data, name->len);
    *((char *) func + name->len) = '\0';

    lua_getglobal(L, (const char *) func);

    if (lua_type(L, -1) != LUA_TFUNCTION) {
        ngx_log_error(NGX_LOG_ERR, lua->log, 0,
                      "can't find function: %s", func);
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t 
ngx_lua_call(ngx_lua_ctx_t *lua, ngx_event_t *wake)
{
    int           status, nresults;
    lua_State    *L;
    const char   *msg;
    ngx_event_t  *pwake;

    L = lua->state;

    if (wake) {
        lua->wake = wake;
        status = lua_resume(L, NULL, lua->nargs, &nresults);
        if (status == LUA_OK) {
            lua->nargs = 0;
            lua->wake = NULL;
        }

    } else {
        pwake = lua->wake;
        lua->wake = NULL;
        status = lua_pcall(L, 1, 1, 0);
        lua->wake = pwake;
    }

    switch (status) {

    case LUA_YIELD:
        if (lua->wake == NULL) {
            ngx_log_error(NGX_LOG_ERR, lua->log, 0,
                          "async calls are not allowed");
            return NGX_ERROR;
        }

        return NGX_AGAIN;

    case LUA_OK:
        return NGX_OK;

    default:
        msg = lua_tostring(lua->state, -1);
        ngx_log_error(NGX_LOG_ERR, lua->log, 0, "lua exception: %s", msg);

        return NGX_ERROR;
    }
}


int
ngx_lua_yield(ngx_lua_ctx_t *lua)
{
    if (lua->wake) {
        return lua_yield(lua->state, 0);
    }

    return luaL_error(lua->state, "blocking calls are not allowed");
}


void
ngx_lua_wakeup(ngx_lua_ctx_t *lua)
{
    ngx_post_event(lua->wake, &ngx_posted_events);
}


void
ngx_lua_core_register(lua_State *L)
{
    lua_createtable(L, 0, 100);

    ngx_lua_log_register(L);

    lua_pushcfunction(L, ngx_lua_base64_encode);
    lua_setfield(L, -2, "base64_encode");

    lua_pushcfunction(L, ngx_lua_base64_decode);
    lua_setfield(L, -2, "base64_decode");

    lua_pushcfunction(L, ngx_lua_timer);
    lua_setfield(L, -2, "timer");

    ngx_lua_crypto_register(L);

    lua_setglobal(L, "ngx");
}


static void
ngx_lua_log_register(lua_State *L)
{
    lua_pushinteger(L, NGX_LOG_STDERR);
    lua_setfield(L, -2, "LOG_STDERR");

    lua_pushinteger(L, NGX_LOG_EMERG);
    lua_setfield(L, -2, "LOG_EMERG");

    lua_pushinteger(L, NGX_LOG_ALERT);
    lua_setfield(L, -2, "LOG_ALERT");

    lua_pushinteger(L, NGX_LOG_CRIT);
    lua_setfield(L, -2, "LOG_CRIT");

    lua_pushinteger(L, NGX_LOG_ERR);
    lua_setfield(L, -2, "LOG_ERR");

    lua_pushinteger(L, NGX_LOG_WARN);
    lua_setfield(L, -2, "LOG_WARN");

    lua_pushinteger(L, NGX_LOG_NOTICE);
    lua_setfield(L, -2, "LOG_NOTICE");

    lua_pushinteger(L, NGX_LOG_INFO);
    lua_setfield(L, -2, "LOG_INFO");

    lua_pushinteger(L, NGX_LOG_DEBUG);
    lua_setfield(L, -2, "LOG_DEBUG");

    lua_pushcfunction(L, ngx_lua_log);
    lua_setfield(L, -2, "log");
}


static int
ngx_lua_log(lua_State *L)
{
    int        n, level;
    ngx_str_t  msg;

    n = lua_gettop(L);
    if (n != 2) {
        return luaL_error(L, "invalid arguments");
    }

    level = luaL_checkinteger(L, 1);
    if (level < NGX_LOG_STDERR || level > NGX_LOG_DEBUG) {
        return luaL_error(L, "invalid level");
    }

    msg.data = (u_char *) luaL_checklstring(L, 2, &msg.len);

    ngx_log_error((ngx_uint_t) level, ngx_cycle->log, 0,
                  "lua: %*s", msg.len, msg.data);

    return 0;
}


static int
ngx_lua_base64_encode(lua_State *L)
{
    ngx_str_t       src, dst;
    ngx_lua_ctx_t  *lua;
    lua = ngx_lua_get_ext(L);

    src.data = (u_char *) luaL_checklstring(L, 1, &src.len);

    dst.len = ngx_base64_encoded_length(src.len);
    dst.data = ngx_pcalloc(lua->pool, dst.len);

    if (dst.data == NULL) {
        return 0;
    }

    ngx_encode_base64(&dst, &src);

    lua_pushlstring(L, (const char *) dst.data, dst.len);

    return 1;
}


static int
ngx_lua_base64_decode(lua_State *L)
{
    ngx_str_t       src, dst;
    ngx_lua_ctx_t  *lua;
    lua = ngx_lua_get_ext(L);

    src.data = (u_char *) luaL_checklstring(L, 1, &src.len);

    dst.len = ngx_base64_decoded_length(src.len);
    dst.data = ngx_pcalloc(lua->pool, dst.len);

    if (dst.data == NULL) {
        return 0;
    }

    ngx_decode_base64(&dst, &src);

    lua_pushlstring(L, (const char *) dst.data, dst.len);

    return 1;
}


static void
ngx_lua_timer_handler(ngx_event_t *ev)
{
    ngx_int_t         rc;
    lua_State        *L;
    ngx_lua_ctx_t    *lua;
    ngx_lua_timer_t  *timer;

    timer = ev->data;
    lua = timer->lua;
    L = lua->state;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ngx_cycle->log, 0,
                   "lua timer() event handler");

    if (lua->wake == NULL) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, timer->handler);
        lua_pushvalue(L, 1);
        luaL_unref(L, LUA_REGISTRYINDEX, timer->handler);
    }

    rc = ngx_lua_call(lua, ev);

    if (rc == NGX_OK) {
        ngx_lua_destroy(lua);
    }
}


static int
ngx_lua_timer(lua_State *L)
{
    int               timeout;
    ngx_event_t      *e;
    ngx_lua_ctx_t    *lua;
    ngx_lua_timer_t  *timer;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, lua->log, 0, "lua timer()");

    lua = ngx_lua_get_ext(L);

    timeout = luaL_checkinteger(L, 1);
    luaL_checktype(L, 2, LUA_TFUNCTION);

    lua = ngx_lua_create(lua->main, lua->log);
    if (lua == NULL) {
        return 0;
    }

    e = ngx_pcalloc(lua->pool, sizeof(ngx_event_t));
    if (e == NULL) {
        return 0;
    }

    timer = ngx_pcalloc(lua->pool, sizeof(ngx_lua_timer_t));
    if (timer == NULL) {
        return 0;
    }

    timer->lua = lua;
    timer->handler = luaL_ref(L, LUA_REGISTRYINDEX);

    e->data = timer;
    e->handler = ngx_lua_timer_handler;
    e->log = ngx_cycle->log;

    ngx_add_timer(e, timeout);

    return 0;
}
