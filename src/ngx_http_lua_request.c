
/*
 * Copyright (C) Jedo Hong
 * Copyright (C) <hongzhidao@gmail.com>
 */


#include <ngx_http_lua.h>


static int ngx_http_lua_req_remote_addr(lua_State *L);
static int ngx_http_lua_get_arg(lua_State *L);
static int ngx_http_lua_get_header_in(lua_State *L);
static int ngx_http_lua_get_header_out(lua_State *L);
static int ngx_http_lua_set_header_out(lua_State *L);
static int ngx_http_lua_get_variable(lua_State *L);
static int ngx_http_lua_req_method(lua_State *L);
static int ngx_http_lua_req_uri(lua_State *L);
static int ngx_http_lua_req_http_version(lua_State *L);
static int ngx_http_lua_req_body(lua_State *L);
static int ngx_http_lua_get_status(lua_State *L);
static int ngx_http_lua_set_status(lua_State *L);


void
ngx_http_lua_register_request(lua_State *L)
{
    /* args { */
    lua_newtable(L);

    lua_createtable(L, 0, 4);
    lua_pushcfunction(L, ngx_http_lua_get_arg);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "arg");
    /* } args */

    /* headers in { */
    lua_newtable(L);

    lua_createtable(L, 0, 4);
    lua_pushcfunction(L, ngx_http_lua_get_header_in);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "header");
    /* } headers in */

    /* headers out { */
    lua_newtable(L);

    lua_createtable(L, 0, 4);
    lua_pushcfunction(L, ngx_http_lua_get_header_out);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, ngx_http_lua_set_header_out);
    lua_setfield(L, -2, "__newindex");
    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "headers");
    /* } headers out */

    /* var { */
    lua_newtable(L);

    lua_createtable(L, 0, 4);
    lua_pushcfunction(L, ngx_http_lua_get_variable);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -2);

    lua_setfield(L, -2, "var");
    /* } var */

    /* __meta { */
    lua_createtable(L, 0, 4);

    lua_pushcfunction(L, ngx_http_lua_req_remote_addr);
    lua_setfield(L, -2, "remote_addr");

    lua_pushcfunction(L, ngx_http_lua_req_method);
    lua_setfield(L, -2, "method");

    lua_pushcfunction(L, ngx_http_lua_req_uri);
    lua_setfield(L, -2, "uri");

    lua_pushcfunction(L, ngx_http_lua_req_http_version);
    lua_setfield(L, -2, "http_version");

    lua_pushcfunction(L, ngx_http_lua_req_body);
    lua_setfield(L, -2, "request_body");

    lua_pushcfunction(L, ngx_http_lua_get_status);
    lua_setfield(L, -2, "status");

    ngx_http_lua_set_meta(L, -2);
    /* } __meta */

    /* __newmeta { */
    lua_createtable(L, 0, 4);

    lua_pushcfunction(L, ngx_http_lua_set_status);
    lua_setfield(L, -2, "status");

    ngx_http_lua_set_newmeta(L, -2);
    /* } __newmeta */

    /* metatable { */
    lua_createtable(L, 0, 4);
    lua_pushcfunction(L, ngx_http_lua_get_index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, ngx_http_lua_set_index);
    lua_setfield(L, -2, "__newindex");
    lua_setmetatable(L, -2);
    /* } metatable */
}


static int
ngx_http_lua_req_remote_addr(lua_State *L)
{
    ngx_connection_t           *c;
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);
    c = r->connection;

    lua_pushlstring(L, (const char *) c->addr_text.data, c->addr_text.len);

    return 1;
}


static int
ngx_http_lua_get_arg(lua_State *L)
{
    ngx_str_t                   name, arg;
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    name.data = (u_char *) luaL_checklstring(L, -1, &name.len);

    if (ngx_http_arg(r, name.data, name.len, &arg) == NGX_OK) {
        lua_pushlstring(L, (const char *) arg.data, (size_t) arg.len);

    } else {
        lua_pushnil(L);
    }

    return 1;
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
ngx_http_lua_get_header_in(lua_State *L)
{
    ngx_str_t                   name;
    ngx_table_elt_t            *h;
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    name.data = (u_char *) luaL_checklstring(L, -1, &name.len);

    h = ngx_http_lua_get_header(&r->headers_in.headers.part, name.data, name.len);

    if (h == NULL) {
        lua_pushnil(L);

    } else {
        lua_pushlstring(L, (const char *) h->value.data, (size_t) h->value.len);
    }

    return 1;
}


static int
ngx_http_lua_get_header_out(lua_State *L)
{
    ngx_str_t                   name;
    ngx_table_elt_t            *h;
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    name.data = (u_char *) luaL_checklstring(L, -1, &name.len);

    h = ngx_http_lua_get_header(&r->headers_out.headers.part, name.data, name.len);

    if (h == NULL) {
        lua_pushnil(L);

    } else {
        lua_pushlstring(L, (const char *) h->value.data, (size_t) h->value.len);
    }

    return 1;
}


static int
ngx_http_lua_set_header_out(lua_State *L)
{
    u_char                     *p;
    ngx_int_t                   n;
    ngx_str_t                   name, value;
    ngx_table_elt_t            *h;
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    name.data = (u_char *) luaL_checklstring(L, -2, &name.len);
    value.data = (u_char *) luaL_checklstring(L, -1, &value.len);

    h = ngx_http_lua_get_header(&r->headers_out.headers.part, name.data, name.len);

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


static int
ngx_http_lua_get_variable(lua_State *L)
{
    ngx_str_t                   name;
    ngx_uint_t                  key;
    ngx_http_request_t         *r;
    ngx_http_variable_value_t  *vv;

    r = ngx_http_lua_get_request(L);

    name.data = (u_char *) luaL_checklstring(L, -1, &name.len);

    key = ngx_hash_strlow(name.data, name.data, name.len);

    vv = ngx_http_get_variable(r, &name, key);

    if (vv == NULL || vv->not_found) {
        lua_pushnil(L);

    } else {
        lua_pushlstring(L, (const char *) vv->data, (size_t) vv->len);
    }

    return 1;
}


static int
ngx_http_lua_req_method(lua_State *L)
{
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    lua_pushlstring(L, (const char *) r->method_name.data, (size_t) r->method_name.len);

    return 1;
}


static int
ngx_http_lua_req_uri(lua_State *L)
{
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    lua_pushlstring(L, (const char *) r->uri.data, (size_t) r->uri.len);

    return 1;
}


static int
ngx_http_lua_req_http_version(lua_State *L)
{
    ngx_str_t                   v;
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    switch (r->http_version) {

    case NGX_HTTP_VERSION_9:
        ngx_str_set(&v, "0.9");
        break;

    case NGX_HTTP_VERSION_10:
        ngx_str_set(&v, "1.0");
        break;

    default: /* NGX_HTTP_VERSION_11 */
        ngx_str_set(&v, "1.1");
        break;
    }

    lua_pushlstring(L, (const char *) v.data, v.len);

    return 1;
}


static int
ngx_http_lua_req_body(lua_State *L)
{
    u_char                     *p;
    size_t                      len;
    ngx_buf_t                  *buf;
    ngx_str_t                   v;
    ngx_chain_t                *cl;
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    if (r->request_body == NULL
        || r->request_body->bufs == NULL
        || r->request_body->temp_file)
    {
        lua_pushnil(L);
        return 1;
    }

    cl = r->request_body->bufs;
    buf = cl->buf;

    if (cl->next == NULL) {
        v.data = buf->pos;
        v.len = buf->last - buf->pos;
        goto found;
    }

    len = buf->last - buf->pos;
    cl = cl->next;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        len += buf->last - buf->pos;
    }

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return luaL_error(L, "get request body failed");
    }

    v.data = p;
    v.len = len;

    cl = r->request_body->bufs;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
    }

found:

    lua_pushlstring(L, (const char *) v.data, v.len);

    return 1;
}


static int
ngx_http_lua_get_status(lua_State *L)
{
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    lua_pushinteger(L, r->headers_out.status);

    return 1;
}


static int
ngx_http_lua_set_status(lua_State *L)
{
    ngx_int_t            n;
    ngx_http_request_t  *r;

    r = ngx_http_lua_get_request(L);

    n = luaL_checkinteger(L, -1);

    r->headers_out.status = n;

    return 0;
}
