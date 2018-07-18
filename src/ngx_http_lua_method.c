
/*
 * Copyright (C) Jedo Hong
 * Copyright (C) <hongzhidao@gmail.com>
 */


#include <ngx_http_lua.h>


static int ngx_http_lua_exit(lua_State *L);
static int ngx_http_lua_log(lua_State *L);
static int ngx_http_lua_warn(lua_State *L);
static int ngx_http_lua_error(lua_State *L);
static int ngx_http_lua_header_in(lua_State *L);
static int ngx_http_lua_header_out(lua_State *L);
static int ngx_http_lua_read_body(lua_State *L);


void
ngx_http_lua_register_method(lua_State *L)
{
    lua_pushcfunction(L, ngx_http_lua_exit);
    lua_setfield(L, -2, "exit");

    lua_pushcfunction(L, ngx_http_lua_log);
    lua_setfield(L, -2, "log");

    lua_pushcfunction(L, ngx_http_lua_warn);
    lua_setfield(L, -2, "warn");

    lua_pushcfunction(L, ngx_http_lua_error);
    lua_setfield(L, -2, "error");

    lua_pushcfunction(L, ngx_http_lua_header_in);
    lua_setfield(L, -2, "header_in");

    lua_pushcfunction(L, ngx_http_lua_header_out);
    lua_setfield(L, -2, "header_out");

    lua_pushcfunction(L, ngx_http_lua_read_body);
    lua_setfield(L, -2, "read_body");
}


static int
ngx_http_lua_exit(lua_State *L)
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


static ngx_table_elt_t *
ngx_http_lua_get_header(ngx_list_part_t *part, u_char *data, size_t len)
{
    ngx_uint_t        i;
    ngx_table_elt_t  *header, *h;

    header = part->elts;

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        h = &header[i];

        if (h->hash == 0) {
            continue;
        }

        if (h->key.len == len && ngx_strncasecmp(h->key.data, data, len) == 0) {
            return h;
        }
    }

    return NULL;
}


static int
ngx_http_lua_header_in(lua_State *L)
{
    ngx_str_t                   name;
    ngx_table_elt_t            *h;
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    name.data = (u_char *) luaL_checklstring(L, 1, &name.len);

    h = ngx_http_lua_get_header(&r->headers_in.headers.part, name.data, name.len);

    if (h == NULL) {
        lua_pushnil(L);

    } else {
        lua_pushlstring(L, (const char *) h->value.data, (size_t) h->value.len);
    }

    return 1;
}


static int
ngx_http_lua_header_out(lua_State *L)
{
    u_char                     *p;
    ngx_int_t                   n;
    ngx_str_t                   name, value;
    ngx_table_elt_t            *h;
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    name.data = (u_char *) luaL_checklstring(L, 1, &name.len);

    h = ngx_http_lua_get_header(&r->headers_out.headers.part, name.data, name.len);

    if (lua_gettop(L) == 1) {

        /* get */

        if (h == NULL) {
            lua_pushnil(L);

        } else {
            lua_pushlstring(L, (const char *) h->value.data, (size_t) h->value.len);
        }

        return 1;
    }

    /* set */

    if (h == NULL || h->hash == 0) {
        h = ngx_list_push(&r->headers_out.headers);
        if (h == NULL) {
            return luaL_error(L, "set headers out failed");
        }

        p = ngx_pnalloc(r->pool, name.len);
        if (p == NULL) {
            return luaL_error(L, "set headers out failed");
        }

        ngx_memcpy(p, name.data, name.len);

        h->key.data = p;
        h->key.len = name.len;
        h->hash = 1;
    }

    value.data = (u_char *) luaL_checklstring(L, 2, &value.len);

    p = ngx_pnalloc(r->pool, value.len);
    if (p == NULL) {
        return luaL_error(L, "set headers out failed");
    }

    ngx_memcpy(p, value.data, value.len);

    h->value.data = p;
    h->value.len = value.len;

    if (h->key.len == sizeof("Content-Length") - 1
        && ngx_strncasecmp(h->key.data, (u_char *) "Content-Length",
                           sizeof("Content-Length") - 1) == 0)
    {
        n = ngx_atoi(value.data, value.len);
        if (n == NGX_ERROR) {
            return luaL_error(L, "set headers out failed");
        }

        r->headers_out.content_length_n = n;
        r->headers_out.content_length = h;
    }

    return 1;
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
