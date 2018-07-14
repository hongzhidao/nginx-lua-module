
/*
 * Copyright (C) Jedo Hong
 * Copyright (C) <hongzhidao@gmail.com>
 */


#include <ngx_http_lua.h>


static int ngx_http_lua_finish(lua_State *L);
static int ngx_http_lua_log(lua_State *L);
static int ngx_http_lua_warn(lua_State *L);
static int ngx_http_lua_error(lua_State *L);
static int ngx_http_lua_read_body(lua_State *L);


void
ngx_http_lua_register_method(lua_State *L)
{
    lua_pushcfunction(L, ngx_http_lua_finish);
    lua_setfield(L, -2, "finish");

    lua_pushcfunction(L, ngx_http_lua_log);
    lua_setfield(L, -2, "log");

    lua_pushcfunction(L, ngx_http_lua_warn);
    lua_setfield(L, -2, "warn");

    lua_pushcfunction(L, ngx_http_lua_error);
    lua_setfield(L, -2, "error");

    lua_pushcfunction(L, ngx_http_lua_read_body);
    lua_setfield(L, -2, "read_body");
}


static int
ngx_http_lua_finish(lua_State *L)
{
    int                        n;
    ngx_str_t                  text;
    ngx_int_t                  status;
    ngx_http_request_t        *r;
    ngx_http_lua_ctx_t        *ctx;
    ngx_http_complex_value_t   cv;

    r = ngx_http_lua_get_request(L);

    n = lua_gettop(L);
    if (n < 1) {
        return luaL_error(L, "too few arguments");
    }

    status = luaL_checkinteger(L, 1);

    if (status < 0 || status > 999) {
        return luaL_error(L, "code is out of range");
    }

    if (n < 2) {
        text.data = NULL;
        text.len = 0;

    } else {
        text.data = (u_char *) luaL_checklstring(L, 2, &text.len);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    if (status < NGX_HTTP_BAD_REQUEST || text.len) {
        ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

        cv.value.data = text.data;
        cv.value.len = text.len;

        ctx->status = ngx_http_send_response(r, status, NULL, &cv);

        if (ctx->status == NGX_ERROR) {
            return luaL_error(L, "failed to send response");
        }

    } else {
        ctx->status = status;
    }

    return 0;
}


static int
ngx_http_lua_log_core(lua_State *L, ngx_uint_t level)
{
    int                        n;
    ngx_str_t                  msg;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_log_handler_pt         handler;

    r = ngx_http_lua_get_request(L);
    c = r->connection;

    n = lua_gettop(L);
    if (n < 1) {
        return luaL_error(L, "too few arguments");
    }

    msg.data = (u_char *) luaL_checklstring(L, 1, &msg.len);

    handler = c->log->handler;
    c->log->handler = NULL;

    ngx_log_error(level, c->log, 0, "lua: %*s", msg.len, msg.data);

    c->log->handler = handler;

    return 0;
}


static int
ngx_http_lua_log(lua_State *L)
{
    return ngx_http_lua_log_core(L, NGX_LOG_INFO);
}


static int
ngx_http_lua_warn(lua_State *L)
{
    return ngx_http_lua_log_core(L, NGX_LOG_WARN);
}


static int
ngx_http_lua_error(lua_State *L)
{
    return ngx_http_lua_log_core(L, NGX_LOG_ERR);
}


static void
ngx_http_lua_body_handler(ngx_http_request_t *r)
{
    ngx_http_lua_ctx_t       *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    r->preserve_body = 1;

    if (ctx->wait) {
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_lua_wakeup(ctx);
    }
}


static int
ngx_http_lua_read_body(lua_State *L)
{
    ngx_int_t                  rc;
    ngx_http_request_t        *r;
    ngx_http_lua_ctx_t        *ctx;

    r = ngx_http_lua_get_request(L);
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    r->request_body_in_single_buf = 1;
    r->request_body_in_persistent_file = 1;
    r->request_body_in_clean_file = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_lua_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return luaL_error(L, "read body error");
    }

    r->main->count--;

    if (rc == NGX_AGAIN) {
        return ngx_http_lua_yield(r);
    }

    return 0;
}
