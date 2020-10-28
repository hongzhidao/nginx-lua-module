
/*
 * Copyright (C) hongzhidao
 */

#ifndef _NGX_LUA_H_INCLUDED_
#define _NGX_LUA_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_unit.h>
#include <ngx_mp.h>
#include <lualib.h>
#include <lauxlib.h>


typedef struct {
    ngx_log_t                  *log;
    ngx_pool_t                 *pool;
    ngx_uint_t                  nargs;
    ngx_event_t                *wake;
    int                         ref;
    lua_State                  *state;
    lua_State                  *main;
    void                       *data;
} ngx_lua_ctx_t;


ngx_lua_ctx_t *ngx_lua_create(lua_State *L, ngx_log_t *log);
void ngx_lua_destroy(ngx_lua_ctx_t *lua);
ngx_int_t ngx_lua_get_function(ngx_lua_ctx_t *lua, ngx_str_t *name);
ngx_int_t ngx_lua_call(ngx_lua_ctx_t *lua, ngx_event_t *wake);
int ngx_lua_yield(ngx_lua_ctx_t *lua);
void ngx_lua_wakeup(ngx_lua_ctx_t *lua);
void ngx_lua_core_register(lua_State *L);
void ngx_lua_crypto_register(lua_State *L);


#define ngx_lua_get_ext(L)                                          \
    (*((void **) lua_getextraspace(L)))

#define ngx_lua_set_ext(L, ext)                                     \
    *((void **) lua_getextraspace(L)) = ext;


#endif /* _NGX_LUA_H_INCLUDED_ */
