
/*
 * Copyright (C) Jedo Hong
 */

#ifndef _NGX_HTTP_LUA_H_INCLUDED_
#define _NGX_HTTP_LUA_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>


typedef struct {
    ngx_str_t                   file;
    lua_State                  *state;
} ngx_http_lua_main_conf_t;


typedef struct {
    ngx_str_t                   access;
    ngx_str_t                   content;
    ngx_str_t                   header_filter;
} ngx_http_lua_loc_conf_t;


typedef struct {
    int                         ref;
    lua_State                  *thread;
    ngx_int_t                   status;
    ngx_event_t                *wake;
    ngx_flag_t                  wait;
} ngx_http_lua_ctx_t;


enum {
    NGX_HTTP_LUA_META_INDEX = 1,
    NGX_HTTP_LUA_META_NEWINDEX,
    NGX_HTTP_LUA_SHM_INDEX,
};


ngx_int_t ngx_http_lua_init_state(ngx_conf_t *cf,
    ngx_http_lua_main_conf_t *lmcf);
int ngx_http_lua_get_index(lua_State *L);
int ngx_http_lua_set_index(lua_State *L);
void ngx_http_lua_register_request(lua_State *L);
void ngx_http_lua_register_global(lua_State *L);
int ngx_http_lua_fetch(lua_State *L);
ngx_int_t ngx_http_lua_resume(ngx_http_request_t *r, ngx_str_t *name,
    ngx_event_t *wake);
ngx_int_t ngx_http_lua_eval(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *result);
int ngx_http_lua_yield(ngx_http_request_t *r);
void ngx_http_lua_wakeup(ngx_http_lua_ctx_t *ctx);


#define                                                             \
ngx_http_lua_set_request(L, r)                                      \
    *((void **)lua_getextraspace(L)) = r


#define                                                             \
ngx_http_lua_get_request(L)                                         \
    (ngx_http_request_t*) (*((void **) lua_getextraspace(L)))


#define                                                             \
ngx_http_lua_get_meta(L, index)                                     \
    lua_rawgeti(L, index, NGX_HTTP_LUA_META_INDEX);


#define                                                             \
ngx_http_lua_set_meta(L, index)                                     \
    lua_rawseti(L, index, NGX_HTTP_LUA_META_INDEX);


#define                                                             \
ngx_http_lua_get_newmeta(L, index)                                  \
    lua_rawgeti(L, index, NGX_HTTP_LUA_META_NEWINDEX);


#define                                                             \
ngx_http_lua_set_newmeta(L, index)                                  \
    lua_rawseti(L, index, NGX_HTTP_LUA_META_NEWINDEX);


static ngx_inline ngx_int_t
ngx_http_lua_err(lua_State *L, ngx_log_t *log)
{
    const char *msg = lua_tostring(L, -1);

    ngx_log_error(NGX_LOG_ERR, log, 0, "lua exception: %s", msg);

    return NGX_ERROR;
}


extern ngx_module_t  ngx_http_lua_module;


#endif /* _NGX_HTTP_LUA_H_INCLUDED_ */
