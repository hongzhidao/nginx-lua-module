
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
    ngx_array_t                 shm_zones;  /* of ngx_shm_zone_t* */
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


typedef struct {
    u_char                       color;
    u_char                       dummy;
    u_short                      key_len;
    uint32_t                     value_len;
    uint8_t                      value_type;
    ngx_queue_t                  queue;
    ngx_msec_t                   expired;
    u_char                       data[1];
} ngx_http_lua_shm_node_t;


typedef struct {
    ngx_rbtree_t                 rbtree;
    ngx_rbtree_node_t            sentinel;
    ngx_queue_t                  queue;
} ngx_http_lua_shm_table_t;


typedef struct {
    ngx_rbtree_t                 rbtree;
    ngx_rbtree_node_t            sentinel;
    ngx_queue_t                  queue;
} ngx_http_lua_shm_shctx_t;


typedef struct {
    ngx_http_lua_shm_shctx_t    *sh;
    ngx_slab_pool_t             *shpool;
} ngx_http_lua_shm_ctx_t;


enum {
    NGX_HTTP_LUA_META_INDEX = 1,
    NGX_HTTP_LUA_META_NEWINDEX,
    NGX_HTTP_LUA_SHM_INDEX,
};


ngx_int_t ngx_http_lua_init_state(ngx_conf_t *cf,
    ngx_http_lua_main_conf_t *lmcf);
int ngx_http_lua_get_index(lua_State *L);
int ngx_http_lua_set_index(lua_State *L);
void ngx_http_lua_register_shm(lua_State *L,
    ngx_http_lua_main_conf_t *lmcf);
void ngx_http_lua_register_meta(lua_State *L);

ngx_int_t ngx_http_lua_resume(ngx_http_request_t *r, ngx_str_t *name,
    ngx_event_t *wake);
ngx_int_t ngx_http_lua_eval(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *result);
int ngx_http_lua_yield(ngx_http_request_t *r);
void ngx_http_lua_wakeup(ngx_http_lua_ctx_t *ctx);

void ngx_http_lua_shm_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
ngx_int_t ngx_http_lua_shm_lookup( ngx_rbtree_t *rbtree, uint32_t hash, 
    ngx_str_t *key, ngx_http_lua_shm_node_t **lnp);

ngx_int_t ngx_http_lua_shm_set_table(ngx_http_request_t *r, lua_State *L,
    ngx_http_lua_shm_ctx_t *ctx, ngx_http_lua_shm_table_t *table, int index);
ngx_http_lua_shm_table_t *ngx_http_lua_shm_get_table(lua_State *L, 
    ngx_http_lua_shm_node_t *ln, int n);
void ngx_http_lua_shm_free_table(ngx_http_lua_shm_ctx_t *ctx,
    ngx_http_lua_shm_node_t *ln);
void ngx_http_lua_shm_destroy_table(ngx_http_lua_shm_ctx_t *ctx,
    ngx_http_lua_shm_table_t *table);


#define                                                             \
ngx_http_lua_set_request(L, r)                                      \
    *((void **)lua_getextraspace(L)) = r


#define                                                             \
ngx_http_lua_get_request(L)                                         \
    (ngx_http_request_t*) (*((void **) lua_getextraspace(L)))


static ngx_inline u_char *
ngx_http_lua_get_error(lua_State *L)
{
    const char *msg = lua_tostring(L, -1);

    return (u_char *) msg;
}


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


#define                                                             \
ngx_http_lua_get_shm(L, index)                                      \
    lua_rawgeti(L, index, NGX_HTTP_LUA_SHM_INDEX);


#define                                                             \
ngx_http_lua_set_shm(L, index)                                      \
    lua_rawseti(L, index, NGX_HTTP_LUA_SHM_INDEX);


static ngx_inline ngx_shm_zone_t *
ngx_http_lua_shm_get_zone(lua_State *L, int index)
{
    ngx_shm_zone_t  *zone;

    luaL_checktype(L, index, LUA_TTABLE);

    ngx_http_lua_get_shm(L, index)

    zone = lua_touserdata(L, -1);

    lua_pop(L, 1);

    return zone;
}


static ngx_inline ngx_http_lua_shm_table_t *
ngx_http_lua_shm_get_table_head(ngx_http_lua_shm_node_t *ln)
{
    return (ngx_http_lua_shm_table_t *)
                ngx_align_ptr(((u_char *) ln->data + ln->key_len), NGX_ALIGNMENT);
}


extern ngx_module_t  ngx_http_lua_module;


#endif /* _NGX_HTTP_LUA_H_INCLUDED_ */
