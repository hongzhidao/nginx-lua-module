
/*
 * Copyright (C) hongzhidao
 */


#include <ngx_lua.h>
#include <ngx_http.h>


typedef struct {
    ngx_str_t                   file;
    ngx_str_t                   worker;
    lua_State                  *state;
} ngx_http_lua_main_conf_t;


typedef struct {
    ngx_str_t                   access;
    ngx_str_t                   content;
    ngx_str_t                   header_filter;
} ngx_http_lua_loc_conf_t;


typedef struct {
    ngx_lua_ctx_t              *lua;
    ngx_int_t                   status;
} ngx_http_lua_ctx_t;


typedef struct {
    ngx_str_t                   name;
    int                       (*handler)(lua_State *L, ngx_http_request_t *r,
                                  ngx_list_t *headers, ngx_str_t *name,
                                  ngx_flag_t isset);

}  ngx_http_lua_header_t;


static void ngx_http_lua_content_event_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_lua_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_http_lua_ctx_t *ngx_http_lua_get_ctx(ngx_http_request_t *r);
static void ngx_http_lua_cleanup_thread(void *data);
static ngx_int_t ngx_http_lua_process_init(ngx_cycle_t *cycle);
static void ngx_http_lua_worker_handler(ngx_event_t *ev);
static ngx_int_t ngx_http_lua_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_lua_init_state(ngx_conf_t *cf,
    ngx_http_lua_main_conf_t *lmcf);
static void ngx_http_lua_cleanup_state(void *data);
static void *ngx_http_lua_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_lua_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_lua_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_lua_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_lua_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_lua_content(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void ngx_lua_http_register(lua_State *L);
static int ngx_http_lua_index(lua_State *L);
static int ngx_http_lua_remote_addr(lua_State *L);
static int ngx_http_lua_method(lua_State *L);
static int ngx_http_lua_host(lua_State *L);
static int ngx_http_lua_uri(lua_State *L);
static int ngx_http_lua_http_version(lua_State *L);
static int ngx_http_lua_request_body(lua_State *L);
static int ngx_http_lua_status(lua_State *L);
static int ngx_http_lua_arguments(lua_State *L);
static int ngx_http_lua_variable(lua_State *L);
static int ngx_http_lua_req_headers_entries(lua_State *L);
static int ngx_http_lua_req_headers_get(lua_State *L);
static int ngx_http_lua_res_headers_entries(lua_State *L);
static int ngx_http_lua_res_headers_get(lua_State *L);
static int ngx_http_lua_res_headers_set(lua_State *L);
static int ngx_http_lua_res_headers_delete(lua_State *L);
static int ngx_http_lua_log(lua_State *L);
static int ngx_http_lua_response(lua_State *L);
static int ngx_http_lua_exit(lua_State *L);
static int ngx_http_lua_header_in_single(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, ngx_flag_t isset);
static int ngx_http_lua_header_in_cookie(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, ngx_flag_t isset);
static int ngx_http_lua_header_out_single(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, ngx_flag_t isset);
static int ngx_http_lua_header_out_cookie(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, ngx_flag_t isset);
static int ngx_http_lua_header_out_cnt_type(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, ngx_flag_t isset);
static int ngx_http_lua_header_out_cnt_length(lua_State *L,
    ngx_http_request_t *r, ngx_list_t *headers, ngx_str_t *name,
    ngx_flag_t isset);
static int ngx_http_lua_header_out_cnt_encoding(lua_State *L,
    ngx_http_request_t *r, ngx_list_t *headers, ngx_str_t *name,
    ngx_flag_t isset);
static int ngx_http_lua_header_array(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, u_char sep);
static ngx_table_elt_t *ngx_http_lua_find_header(ngx_list_t *headers,
    u_char *data, size_t len);
static ngx_int_t ngx_http_lua_add_header(lua_State *L, ngx_http_request_t *r,
    ngx_str_t *name, int index);
static void ngx_http_lua_del_header(ngx_http_request_t *r, ngx_str_t *name);


static ngx_command_t  ngx_http_lua_commands[] = {

    { ngx_string("lua_include"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_lua_main_conf_t, file),
      NULL },

    { ngx_string("lua_init_worker"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_lua_main_conf_t, worker),
      NULL },

    { ngx_string("lua_set"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_lua_set,
      0,
      0,
      NULL },

    { ngx_string("lua_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lua_loc_conf_t, access),
      NULL },

    { ngx_string("lua_content"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_lua_content,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("lua_header_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_lua_loc_conf_t, header_filter),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_lua_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_lua_init,             /* postconfiguration */

    ngx_http_lua_create_main_conf, /* create main configuration */
    ngx_http_lua_init_main_conf,   /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_lua_create_loc_conf,  /* create location configuration */
    ngx_http_lua_merge_loc_conf    /* merge location configuration */
};


ngx_module_t  ngx_http_lua_module = {
    NGX_MODULE_V1,
    &ngx_http_lua_module_ctx,      /* module context */
    ngx_http_lua_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_lua_process_init,     /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_lua_header_t ngx_http_lua_headers_in[] = {
    { ngx_string("Content-Type"), ngx_http_lua_header_in_single },
    { ngx_string("Cookie"), ngx_http_lua_header_in_cookie },
    { ngx_string("ETag"), ngx_http_lua_header_in_single },
    { ngx_string("From"), ngx_http_lua_header_in_single },
    { ngx_string("Max-Forwards"), ngx_http_lua_header_in_single },
    { ngx_string("Referer"), ngx_http_lua_header_in_single },
    { ngx_string("Proxy-Authorization"), ngx_http_lua_header_in_single },
    { ngx_string("User-Agent"), ngx_http_lua_header_in_single },
    { ngx_null_string, NULL }
};


static ngx_http_lua_header_t ngx_http_lua_headers_out[] = {
    { ngx_string("Age"), ngx_http_lua_header_out_single },
    { ngx_string("Set-Cookie"), ngx_http_lua_header_out_cookie },
    { ngx_string("Content-Type"), ngx_http_lua_header_out_cnt_type },
    { ngx_string("Content-Length"), ngx_http_lua_header_out_cnt_length },
    { ngx_string("Content-Encoding"), ngx_http_lua_header_out_cnt_encoding },
    { ngx_string("Etag"), ngx_http_lua_header_out_single },
    { ngx_string("Expires"), ngx_http_lua_header_out_single },
    { ngx_string("Last-Modified"), ngx_http_lua_header_out_single },
    { ngx_string("Location"), ngx_http_lua_header_out_single },
    { ngx_string("Retry-After"), ngx_http_lua_header_out_single },
    { ngx_null_string, NULL }
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_lua_content_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http lua content handler");

    rc = ngx_http_read_client_request_body(r,
                                           ngx_http_lua_content_event_handler);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
ngx_http_lua_content_event_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_lua_ctx_t                *lua;
    ngx_http_lua_ctx_t           *ctx;
    ngx_http_lua_loc_conf_t      *llcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http lua content event handler");

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    ctx = ngx_http_lua_get_ctx(r);
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    lua = ctx->lua;

    if (lua->wake == NULL) {
        rc = ngx_lua_get_function(lua, &llcf->content);
        if (rc != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return; 
        }

        lua_getglobal(lua->state, "http_prototypes");
        lua->nargs = 1;
    }

    rc = ngx_lua_call(lua, r->connection->write);

    if (rc == NGX_AGAIN) {
        r->write_event_handler = ngx_http_lua_content_event_handler;
        return;
    }

    if (rc == NGX_ERROR) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_http_finalize_request(r, ctx->status);
}


static ngx_int_t
ngx_http_lua_access_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_lua_ctx_t                *lua;
    ngx_http_lua_ctx_t           *ctx;
    ngx_http_lua_loc_conf_t      *llcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http lua access handler");

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    if (llcf->access.len == 0) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_lua_get_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    lua = ctx->lua;

    if (lua->wake == NULL) {
        rc = ngx_lua_get_function(lua, &llcf->access);
        if (rc != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        lua_getglobal(lua->state, "http_prototypes");
        lua->nargs = 1;
    }

    rc = ngx_lua_call(lua, r->connection->write);

    if (rc == NGX_OK && r->header_sent) {
        return NGX_HTTP_OK;
    }

    /* NGX_OK, NGX_AGAIN, NGX_DECLINED, NGX_ERROR, NGX_HTTP_... */

    return rc;
}


static ngx_int_t
ngx_http_lua_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_lua_ctx_t                *lua;
    ngx_http_lua_ctx_t           *ctx;
    ngx_http_lua_loc_conf_t      *llcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http lua header filter handler");

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    if (llcf->header_filter.len == 0) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_lua_get_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    lua = ctx->lua;

    /* Async operations is not allowed in header filter. */

    rc = ngx_lua_get_function(lua, &llcf->header_filter);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    lua_getglobal(lua->state, "http_prototypes");
    lua->nargs = 1;

    rc = ngx_lua_call(lua, NULL);
    if (rc == NGX_ERROR) {
        return rc;
    }

    /* NGX_DECLINED, NGX_OK */

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_lua_variable_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_str_t  *func = (ngx_str_t *) data;

    size_t               len;
    ngx_int_t            rc;
    ngx_lua_ctx_t       *lua;
    ngx_http_lua_ctx_t  *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http lua variable handler");

    ctx = ngx_http_lua_get_ctx(r);
    if (ctx == NULL) {
        return NGX_ERROR;
    }

    lua = ctx->lua;

    rc = ngx_lua_get_function(lua, func);
    if (rc != NGX_OK) {
        return rc;
    }

    lua_getglobal(lua->state, "http_prototypes");
    lua->nargs = 1;

    rc = ngx_lua_call(lua, NULL);
    if (rc == NGX_ERROR) {
        return rc;
    }

    v->data = (u_char *) lua_tolstring(lua->state, -1, &len);
    v->len = len;
    
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
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

    ctx->lua = ngx_lua_create(lmcf->state, r->connection->log);
    if (ctx->lua == NULL) {
        return NULL;
    }

    ctx->lua->data = r;

    ctx->status = NGX_HTTP_INTERNAL_SERVER_ERROR;

    cln = ngx_pool_cleanup_add(r->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_lua_cleanup_thread;
    cln->data = r;

    return ctx;
}


static void
ngx_http_lua_cleanup_thread(void *data)
{
    ngx_http_request_t  *r = data;

    ngx_http_lua_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    ngx_lua_destroy(ctx->lua);
}


static ngx_int_t
ngx_http_lua_process_init(ngx_cycle_t *cycle)
{
    ngx_lua_ctx_t             *lua;
    ngx_connection_t          *c;
    ngx_http_lua_main_conf_t  *lmcf;

    if (ngx_process != NGX_PROCESS_WORKER) {
        return NGX_OK;
    }

    lmcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_lua_module);

    if (lmcf == NULL || lmcf->state == NULL) {
        return NGX_OK;
    }

    lua = ngx_lua_create(lmcf->state, cycle->log);
    if (lua == NULL) {
        return NGX_ERROR;
    }

    c = ngx_pcalloc(cycle->pool, sizeof(ngx_connection_t));
    if (c == NULL) {
        return NGX_ERROR;
    }

    c->data = lua;

    c->write = ngx_pcalloc(cycle->pool, sizeof(ngx_event_t));
    if (c->write == NULL) {
        return NGX_ERROR;
    }

    c->write->handler = ngx_http_lua_worker_handler;
    c->write->data = c;

    if (lmcf->worker.len == 0) {
        return NGX_OK;
    }

    if (ngx_lua_get_function(lua, &lmcf->worker) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_lua_call(lua, c->write);

    return NGX_OK;
}


static void
ngx_http_lua_worker_handler(ngx_event_t *ev)
{
    ngx_lua_ctx_t     *lua;
    ngx_connection_t  *c;

    c = ev->data;
    lua = c->data;

    ngx_lua_call(lua, c->write);
}


static void *
ngx_http_lua_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_lua_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lua_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->state = NULL;
     */

    return conf;
}


static char *
ngx_http_lua_init_main_conf(ngx_conf_t *cf, void *conf)
{
    return NGX_CONF_OK;
}


static void *
ngx_http_lua_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_lua_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_lua_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->access = { 0, NULL };
     *     conf->content = { 0, NULL };
     */

    return conf;
}


static char *
ngx_http_lua_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_lua_loc_conf_t  *prev = parent; 
    ngx_http_lua_loc_conf_t  *conf = child; 

    if (conf->access.data == NULL) {
        conf->access = prev->access;
    }

    if (conf->content.data == NULL) {
        conf->content = prev->content;
    }

    if (conf->header_filter.data == NULL) {
        conf->header_filter = prev->header_filter;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_lua_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t            *value, *func;
    ngx_http_variable_t  *v;

    value = cf->args->elts;

    if (value[1].data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    value[1].len--;
    value[1].data++;

    v = ngx_http_add_variable(cf, &value[1], NGX_HTTP_VAR_CHANGEABLE);
    if (v == NULL) {
        return NGX_CONF_ERROR;
    }

    func = ngx_pcalloc(cf->pool, sizeof(ngx_str_t));
    if (func == NULL) {
        return NGX_CONF_ERROR;
    }

    *func = value[2];

    v->get_handler = ngx_http_lua_variable_handler;
    v->data = (uintptr_t) func;

    return NGX_CONF_OK;
}


static char *
ngx_http_lua_content(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_lua_loc_conf_t *llcf = conf;

    ngx_str_t                 *value;
    ngx_http_core_loc_conf_t  *clcf;

    if (llcf->content.data) {
        return "is duplicate";
    }

    value = cf->args->elts;
    llcf->content = value[1];

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_lua_content_handler;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_lua_init(ngx_conf_t *cf)
{
    ngx_int_t                   rc;
    ngx_http_handler_pt        *h;
    ngx_http_lua_main_conf_t   *lmcf;
    ngx_http_core_main_conf_t  *cmcf;

    lmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_lua_module);
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    rc = ngx_http_lua_init_state(cf, lmcf);

    if (rc == NGX_DECLINED) {
        return NGX_OK;
    }

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "failed to init lua state");
        return NGX_ERROR;
    }

    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_lua_header_filter;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_lua_access_handler;

    return NGX_OK;
}


static ngx_int_t
ngx_http_lua_init_state(ngx_conf_t *cf, ngx_http_lua_main_conf_t *lmcf)
{
    int                    status;
    u_char                *path, *msg;
    lua_State             *L;
    ngx_str_t             *file;
    ngx_pool_cleanup_t    *cln;

    if (lmcf->file.len == 0) {
        return NGX_DECLINED;
    }

    L = luaL_newstate();
    if (L == NULL) {
        return NGX_ERROR;
    }

    luaL_openlibs(L);

    ngx_lua_core_register(L);
    ngx_lua_http_register(L);

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

    msg = (u_char *) lua_tostring(L, -1);

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", msg);

    return NGX_ERROR;
}


static void
ngx_http_lua_cleanup_state(void *data)
{
    lua_State *L = data;

    lua_close(L);
}


static void
ngx_lua_http_register(lua_State *L)
{
    /* http props { */
    lua_createtable(L, 0, 4);

    lua_pushcfunction(L, ngx_http_lua_remote_addr);
    lua_setfield(L, -2, "remote_addr");

    lua_pushcfunction(L, ngx_http_lua_method);
    lua_setfield(L, -2, "method");

    lua_pushcfunction(L, ngx_http_lua_host);
    lua_setfield(L, -2, "host");

    lua_pushcfunction(L, ngx_http_lua_uri);
    lua_setfield(L, -2, "uri");

    lua_pushcfunction(L, ngx_http_lua_http_version);
    lua_setfield(L, -2, "http_version");

    lua_pushcfunction(L, ngx_http_lua_request_body);
    lua_setfield(L, -2, "request_body");

    lua_pushcfunction(L, ngx_http_lua_status);
    lua_setfield(L, -2, "status");

    lua_pushcfunction(L, ngx_http_lua_arguments);
    lua_setfield(L, -2, "args");

    lua_setglobal(L, "http_props");
    /* } http props */

    lua_createtable(L, 0, 100);

    /* ctx { */
    lua_createtable(L, 0, 4);
    lua_setfield(L, -2, "ctx");
    /* } ctx */

    /* vars { */
    lua_newtable(L);
    lua_createtable(L, 0, 4);
    lua_pushcfunction(L, ngx_http_lua_variable);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, ngx_http_lua_variable);
    lua_setfield(L, -2, "__newindex");
    lua_setmetatable(L, -2);
    lua_setfield(L, -2, "vars");
    /* } vars */

    /* req_headers { */
    lua_createtable(L, 0, 4);
    lua_pushcfunction(L, ngx_http_lua_req_headers_entries);
    lua_setfield(L, -2, "entries");
    lua_pushcfunction(L, ngx_http_lua_req_headers_get);
    lua_setfield(L, -2, "get");
    lua_setfield(L, -2, "req_headers");
    /* } req_headers */

    /* res_headers { */
    lua_createtable(L, 0, 4);
    lua_pushcfunction(L, ngx_http_lua_res_headers_entries);
    lua_setfield(L, -2, "entries");
    lua_pushcfunction(L, ngx_http_lua_res_headers_get);
    lua_setfield(L, -2, "get");
    lua_pushcfunction(L, ngx_http_lua_res_headers_set);
    lua_setfield(L, -2, "set");
    lua_pushcfunction(L, ngx_http_lua_res_headers_delete);
    lua_setfield(L, -2, "delete");
    lua_setfield(L, -2, "res_headers");
    /* } res_headers */

    lua_pushcfunction(L, ngx_http_lua_log);
    lua_setfield(L, -2, "log");

    lua_pushcfunction(L, ngx_http_lua_response);
    lua_setfield(L, -2, "response");

    lua_pushcfunction(L, ngx_http_lua_exit);
    lua_setfield(L, -2, "exit");

    /* setmetatable { */
    lua_createtable(L, 0, 4);
    lua_pushcfunction(L, ngx_http_lua_index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, ngx_http_lua_index);
    lua_setfield(L, -2, "__newindex");
    lua_setmetatable(L, -2);
    /* } setmetatable */

    lua_setglobal(L, "http_prototypes");
}


static ngx_http_request_t *
ngx_http_lua_get_request(lua_State *L)
{
    ngx_lua_ctx_t  *lua;

    lua = ngx_lua_get_ext(L);

    return lua->data;
}


static int
ngx_http_lua_index(lua_State *L)
{
    int        n;
    ngx_str_t  name;

    n = lua_gettop(L);

    name.data = (u_char *) luaL_checklstring(L, 2, &name.len);

    lua_getglobal(L, "http_props");
    lua_getfield(L, -1, (const char *) name.data);

    if (!lua_isfunction(L, -1)) {
        lua_pushnil(L);
        return 1;
    }

    if (n == 2) {
        lua_call(L, 0, 1);
        return 1;
    }

    lua_pushvalue(L, -3);
    lua_call(L, 1, 1);

    return 0;
}


static int
ngx_http_lua_remote_addr(lua_State *L)
{
    ngx_connection_t           *c;
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);
    c = r->connection;

    lua_pushlstring(L, (const char *) c->addr_text.data, c->addr_text.len);

    return 1;
}


static int
ngx_http_lua_method(lua_State *L)
{
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    lua_pushlstring(L, (const char *) r->method_name.data, r->method_name.len);

    return 1;
}


static int
ngx_http_lua_host(lua_State *L)
{
    ngx_http_request_t        *r;
    ngx_http_core_srv_conf_t  *cscf;

    r = ngx_http_lua_get_request(L);

    if (r->headers_in.server.len) {
        lua_pushlstring(L, (const char *) r->headers_in.server.data,
                        r->headers_in.server.len);

    } else {
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

        lua_pushlstring(L, (const char *) cscf->server_name.data,
                        cscf->server_name.len);
    }

    return 1;
}


static int
ngx_http_lua_uri(lua_State *L)
{
    ngx_http_request_t         *r;

    r = ngx_http_lua_get_request(L);

    lua_pushlstring(L, (const char *) r->uri.data, r->uri.len);

    return 1;
}


static int
ngx_http_lua_http_version(lua_State *L)
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
ngx_http_lua_request_body(lua_State *L)
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
ngx_http_lua_status(lua_State *L)
{
    int                  n;
    ngx_http_request_t  *r;

    n = lua_gettop(L);
    r = ngx_http_lua_get_request(L);

    if (n == 0) {
        lua_pushinteger(L, r->headers_out.status);
        return 1;
    }

    n = luaL_checkinteger(L, 1);

    r->headers_out.status = n;

    return 0;
}


static int
ngx_http_lua_arguments(lua_State *L)
{
    u_char              *v, *p, *start, *end;
    ngx_http_request_t  *r;

    r = ngx_http_lua_get_request(L);

    lua_createtable(L, 0, 10);

    start = r->args.data;
    end = start + r->args.len;

    while (start < end) {
        p = ngx_strlchr(start, end, '&');
        if (p == NULL) {
            p = end;
        }

        v = ngx_strlchr(start, p, '=');
        if (v == NULL) {
            v = p;
        }

        if (v != start && v < p) {
            lua_pushlstring(L, (const char *) start, v - start);
            lua_pushlstring(L, (const char *) v + 1, p - v - 1);

            lua_settable(L, -3);
        }

        start = p + 1;
    }

    return 1;
}


static int
ngx_http_lua_variable(lua_State *L)
{
    ngx_str_t                   name, val;
    ngx_uint_t                  key;
    ngx_http_request_t         *r;
    ngx_http_variable_t        *v;
    ngx_http_variable_value_t  *vv;
    ngx_http_core_main_conf_t  *cmcf;

    r = ngx_http_lua_get_request(L);

    name.data = (u_char *) luaL_checklstring(L, 2, &name.len);

    ngx_memzero(&val, sizeof(ngx_str_t));

    if (lua_gettop(L) == 3) {
        val.data = (u_char *) luaL_checklstring(L, 3, &val.len);
    }

    key = ngx_hash_strlow(name.data, name.data, name.len);

    if (val.data == NULL) {
        vv = ngx_http_get_variable(r, &name, key);

        if (vv == NULL || vv->not_found) {
            lua_pushnil(L);

        } else {
            lua_pushlstring(L, (const char *) vv->data, (size_t) vv->len);
        }

        return 1;
    }

    cmcf = ngx_http_get_module_main_conf(r, ngx_http_core_module);

    v = ngx_hash_find(&cmcf->variables_hash, key, name.data, name.len);
    if (v == NULL) {
        luaL_error(L, "variable not found");
        return 0;
    }

    if (v->set_handler != NULL) {
        vv = ngx_pcalloc(r->pool, sizeof(ngx_http_variable_value_t));
        if (vv == NULL) {
            return 0;
        }

        vv->valid = 1;
        vv->not_found = 0;
        vv->data = val.data;
        vv->len = val.len;

        v->set_handler(r, vv, v->data);

        return 0;
    }

    if (!(v->flags & NGX_HTTP_VAR_INDEXED)) {
        luaL_error(L, "variable is not writable");
        return 0;
    }

    vv = &r->variables[v->index];

    vv->valid = 1;
    vv->not_found = 0;

    vv->data = ngx_pnalloc(r->pool, val.len);
    if (vv->data == NULL) {
        return 0;
    }

    vv->len = val.len;
    ngx_memcpy(vv->data, val.data, vv->len);

    return 0;
}


static void
ngx_http_lua_headers_entries(lua_State *L, ngx_list_t *headers)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header, *h;

    part = &headers->part;
    i = 0;

    while (part) {
        if (i >= part->nelts) {
            part = part->next;
            i = 0;
            continue;
        }

        header = part->elts;
        h = &header[i++];

        if (h->hash == 0) {
            continue;
        }

        lua_pushlstring(L, (const char *) h->key.data, h->key.len);
        lua_pushlstring(L, (const char *) h->value.data, h->value.len);
        lua_settable(L, -3);
    }
}


static int
ngx_http_lua_req_headers_entries(lua_State *L)
{
    ngx_http_request_t  *r;

    r = ngx_http_lua_get_request(L);

    lua_createtable(L, 0, 10);

    ngx_http_lua_headers_entries(L, &r->headers_in.headers);

    return 1;
}


static int
ngx_http_lua_req_headers_get(lua_State *L)
{
    ngx_str_t               name;
    ngx_http_request_t     *r;
    ngx_http_lua_header_t  *h;

    r = ngx_http_lua_get_request(L);

    name.data = (u_char *) luaL_checklstring(L, 1, &name.len);

    for (h = ngx_http_lua_headers_in; h->handler != NULL; h++) {
        if (h->name.len == name.len
            && ngx_strncasecmp(h->name.data, name.data, name.len) == 0)
        {
            return h->handler(L, r, &r->headers_in.headers, &name, 0);
        }
    }

    return ngx_http_lua_header_array(L, r, &r->headers_in.headers, &name,
                                         ',');
}


static int
ngx_http_lua_res_headers_entries(lua_State *L)
{
    ngx_http_request_t  *r;

    r = ngx_http_lua_get_request(L);

    lua_createtable(L, 0, 10);

    ngx_http_lua_headers_entries(L, &r->headers_out.headers);

    if (r->headers_out.content_type.len) {
        lua_pushlstring(L, "Content-Type", ngx_strlen("Content-Type"));
        lua_pushlstring(L, (const char *) r->headers_out.content_type.data,
                        r->headers_out.content_type.len);
        lua_settable(L, -3);
    }

    if (r->headers_out.content_length == NULL
        && r->headers_out.content_length_n >= 0)
    {
        lua_pushlstring(L, "Content-Length", ngx_strlen("Content-Length"));
        lua_pushinteger(L, r->headers_out.content_length_n);
        lua_settable(L, -3);
    }

    return 1;
}


static int
ngx_http_lua_res_headers_get(lua_State *L)
{
    ngx_str_t               name;
    ngx_list_t             *headers;
    ngx_http_request_t     *r;
    ngx_http_lua_header_t  *h;

    r = ngx_http_lua_get_request(L);
    headers = &r->headers_out.headers;

    name.data = (u_char *) luaL_checklstring(L, 1, &name.len);

    for (h = ngx_http_lua_headers_out; h->handler != NULL; h++) {
        if (h->name.len == name.len
            && ngx_strncasecmp(h->name.data, name.data, name.len) == 0)
        {
            return h->handler(L, r, headers, &name, 0);
        }
    }

    return ngx_http_lua_header_array(L, r, headers, &name, ',');
}


static int
ngx_http_lua_res_headers_set(lua_State *L)
{
    ngx_str_t               name;
    ngx_http_request_t     *r;
    ngx_http_lua_header_t  *h;

    r = ngx_http_lua_get_request(L);

    name.data = (u_char *) luaL_checklstring(L, 1, &name.len);

    for (h = ngx_http_lua_headers_out; h->name.len > 0; h++) {
        if (h->name.len == name.len
            && ngx_strncasecmp(h->name.data, name.data, name.len) == 0)
        {
            return h->handler(L, r, &r->headers_out.headers, &name, 1);
        }
    }

    ngx_http_lua_add_header(L, r, &name, 2);

    return 0;
}


static int
ngx_http_lua_res_headers_delete(lua_State *L)
{
    ngx_str_t            name;
    ngx_http_request_t  *r;

    r = ngx_http_lua_get_request(L);

    name.data = (u_char *) luaL_checklstring(L, 1, &name.len);

    ngx_http_lua_del_header(r, &name);

    return 0;
}


static int
ngx_http_lua_log(lua_State *L)
{
    int                  n, level;
    ngx_str_t            msg;
    ngx_http_request_t  *r;

    r = ngx_http_lua_get_request(L);

    n = lua_gettop(L);
    if (n != 2) {
        return luaL_error(L, "invalid arguments");
    }

    level = luaL_checkinteger(L, 1);
    if (level < NGX_LOG_STDERR || level > NGX_LOG_DEBUG) {
        return luaL_error(L, "invalid level");
    }

    msg.data = (u_char *) luaL_checklstring(L, 2, &msg.len);

    ngx_log_error((ngx_uint_t) level, r->connection->log, 0,
                  "lua: %*s", msg.len, msg.data);

    return 0;
}


static int
ngx_http_lua_response(lua_State *L)
{
    int                        n;
    ngx_int_t                  rc, status;
    ngx_str_t                  body, name;
    ngx_http_request_t        *r;
    ngx_http_lua_ctx_t        *ctx;
    ngx_http_complex_value_t   cv;

    r = ngx_http_lua_get_request(L);
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    n = lua_gettop(L);
    if (n < 1) {
        return luaL_error(L, "too few arguments");
    }

    body.data = (u_char *) luaL_checklstring(L, 1, &body.len);

    if (lua_istable(L, 2)) {
        lua_getfield(L, 2, "status");
        lua_getfield(L, 2, "headers");

    } else if (!lua_isnoneornil(L, 2)) {
        return luaL_error(L, "failed to convert init");

    } else {
        lua_pushnil(L);
        lua_pushnil(L);
        lua_pushnil(L);
    }

    if (lua_isnoneornil(L, 3)) {
        status = r->headers_out.status ? r->headers_out.status : 200;

    } else {
        status = luaL_checkinteger(L, 3);
    }

    if (status < 0 || status > 999) {
        return luaL_error(L, "code is out of range");
    }

    if (!lua_isnil(L, 4)) {
        if (!lua_istable(L, 4)) {
            return luaL_error(L, "failed to convert init.headers");
        }

        lua_pushvalue(L, 4);
        lua_pushnil(L);

        while (lua_next(L, -2)) {
            lua_pushvalue(L, -2);

            name.data = (u_char *) luaL_checklstring(L, -1, &name.len);

            rc = ngx_http_lua_add_header(L, r, &name, -2);
            if (rc != NGX_OK) {
                return 0;
            }

            lua_pop(L, 2);
        }

        lua_pop(L, 1);
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    cv.value.data = body.data;
    cv.value.len = body.len;

    ctx->status = ngx_http_send_response(r, status, NULL, &cv);
    if (ctx->status == NGX_ERROR) {
        return luaL_error(L, "failed to send response");
    }

    return 0;
}


static int
ngx_http_lua_exit(lua_State *L)
{
    ngx_int_t                  status;
    ngx_http_request_t        *r;
    ngx_http_lua_ctx_t        *ctx;
    ngx_http_complex_value_t   cv;

    r = ngx_http_lua_get_request(L);
    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    status = luaL_checkinteger(L, 1);

    if (status < 0 || status > 999) {
        return luaL_error(L, "code is out of range");
    }

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    ctx->status = ngx_http_send_response(r, status, NULL, &cv);
    if (ctx->status == NGX_ERROR) {
        return luaL_error(L, "failed to exit");
    }

    return 0;
}


static int
ngx_http_lua_header_in_single(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, ngx_flag_t isset)
{
    ngx_table_elt_t  *h;

    h = ngx_http_lua_find_header(headers, name->data, name->len);

    if (h == NULL) {
        lua_pushnil(L);

    } else {
        lua_pushlstring(L, (const char *) h->value.data, h->value.len);
    }

    return 1;
}


static int
ngx_http_lua_header_in_cookie(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, ngx_flag_t isset)
{
    u_char            *p, *start, *end;
    size_t             len;
    ngx_uint_t         i, n;
    ngx_array_t       *array;
    ngx_table_elt_t  **hh;

    array = &r->headers_in.cookies;

    n = array->nelts;
    hh = array->elts;

    len = 0;

    for (i = 0; i < n; i++) {
        len += hh[i]->value.len + 1;
    }

    if (len == 0) {
        lua_pushnil(L);
        return 1;
    }

    len -= 1;

    if (n == 1) {
        lua_pushlstring(L, (const char *) (*hh)->value.data, (*hh)->value.len);
        return 1;
    }

    p = ngx_palloc(r->pool, len);
    if (p == NULL) {
        return 0;
    }

    start = p;
    end = p + len;

    for (i = 0; /* void */ ; i++) {
        p = ngx_copy(p, hh[i]->value.data, hh[i]->value.len);

        if (p == end) {
            break;
        }

        *p++ = ';';
    }

    lua_pushlstring(L, (const char *) start, p - start);

    return 1;
}


static ngx_int_t
ngx_http_lua_add_builtin_header(lua_State *L, ngx_http_request_t *r,
    ngx_str_t *name, ngx_table_elt_t **hh)
{
    u_char              *p;
    ngx_str_t            value;
    ngx_list_t          *headers;
    ngx_table_elt_t     *h;

    headers = &r->headers_out.headers;

    value.data = (u_char *) luaL_checklstring(L, 2, &value.len);

    h = ngx_http_lua_find_header(headers, name->data, name->len);

    if (h != NULL && value.len == 0) {
        h->hash = 0;
        h = NULL;
    }
    
    if (h == NULL && value.len != 0) {
        h = ngx_list_push(headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        p = ngx_pnalloc(r->pool, name->len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, name->data, name->len);

        h->key.data = p;
        h->key.len = name->len;
    }

    if (h != NULL) {
        p = ngx_pnalloc(r->pool, value.len);
        if (p == NULL) {
            return NGX_ERROR;
        }

        ngx_memcpy(p, value.data, value.len);

        h->value.data = p;
        h->value.len = value.len;
        h->hash = 1;
    }

    if (hh != NULL) {
        *hh = h;
    }

    return NGX_OK;
}


static int
ngx_http_lua_header_out_single(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, ngx_flag_t isset)
{
    ngx_table_elt_t  *h;

    if (!isset) {
        h = ngx_http_lua_find_header(headers, name->data, name->len);

        if (h == NULL) {
            lua_pushnil(L);

        } else {
            lua_pushlstring(L, (const char *) h->value.data, h->value.len);
        }

        return 1;
    }

    ngx_http_lua_add_header(L, r, name, 2);

    return 0;
}


static int
ngx_http_lua_header_out_cookie(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, ngx_flag_t isset)
{
    if (!isset) {
        return ngx_http_lua_header_array(L, r, headers, name, ';');
    }

    ngx_http_lua_add_header(L, r, name, 2);

    return 0;
}


static int
ngx_http_lua_header_out_cnt_type(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, ngx_flag_t isset)
{
    ngx_str_t  value;

    if (!isset) {
        lua_pushlstring(L, (const char *) r->headers_out.content_type.data,
                        r->headers_out.content_type.len);
        return 1;
    }

    value.data = (u_char *) luaL_checklstring(L, 2, &value.len);

    r->headers_out.content_type.len = value.len;
    r->headers_out.content_type_len = value.len;
    r->headers_out.content_type.data = value.data;
    r->headers_out.content_type_lowcase = NULL;

    return 0;
}


static int
ngx_http_lua_header_out_cnt_length(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, ngx_flag_t isset)
{
    u_char           *p;
    ngx_int_t         n;
    ngx_table_elt_t  *h;
    u_char            content_len[NGX_OFF_T_LEN];

    if (!isset) {
        if (r->headers_out.content_length == NULL
            && r->headers_out.content_length_n >= 0)
        {
            p = ngx_sprintf(content_len, "%O", r->headers_out.content_length_n);

            lua_pushlstring(L, (const char *) content_len, p - content_len);
            return 1;
        }

        return ngx_http_lua_header_out_single(L, r, headers, name, isset);
    }

    if (ngx_http_lua_add_builtin_header(L, r, name, &h) != NGX_OK) {
        return 0;
    }

    if (h != NULL) {
        n = ngx_atoi(h->value.data, h->value.len);
        if (n == NGX_ERROR) {
            h->hash = 0;
            luaL_error(L, "failed converting argument to positive integer");
            return 0;
        }

        r->headers_out.content_length = h;
        r->headers_out.content_length_n = n;

    } else {
        ngx_http_clear_content_length(r);
    }

    return 0;
}


static int
ngx_http_lua_header_out_cnt_encoding(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, ngx_flag_t isset)
{
    ngx_table_elt_t  *h;

    if (!isset) {
        return ngx_http_lua_header_out_single(L, r, headers, name, isset);
    }

    if (ngx_http_lua_add_builtin_header(L, r, name, &h) != NGX_OK) {
        return 0;
    }

    if (isset) {
        r->headers_out.content_encoding = h;
    }

    return 1;
}


static int
ngx_http_lua_header_array(lua_State *L, ngx_http_request_t *r,
    ngx_list_t *headers, ngx_str_t *name, u_char sep)
{
    u_char           *data, *p, *start, *end;
    size_t            len;
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header, *h;

    part = &headers->part;
    header = part->elts;

    p = NULL;
    start = NULL;
    end  = NULL;

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

        if (h->hash == 0
            || h->key.len != name->len
            || ngx_strncasecmp(h->key.data, name->data, name->len) != 0)
        {
            continue;
        }
    
        if (p == NULL) {
            start = h->value.data;
            end = h->value.data + h->value.len;
            p = end;
            continue;
        }

        if (p + h->value.len + 1 > end) {
            len = ngx_max(p + h->value.len + 1 - start, 2 * (end - start));

            data = ngx_pnalloc(r->pool, len);
            if (data == NULL) {
                return 0;
            }

            p = ngx_cpymem(data, start, p - start);
            start = data;
            end = data + len;
        }

        *p++ = ',';
        p = ngx_cpymem(p, h->value.data, h->value.len);
    }

    if (p == NULL) {
        lua_pushnil(L);
        return 1;
    }

    lua_pushlstring(L, (const char *) start, p - start);

    return 1;
}


static ngx_table_elt_t *
ngx_http_lua_find_header(ngx_list_t *headers, u_char *data, size_t len)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header, *h;

    part = &headers->part;
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


static ngx_int_t
ngx_http_lua_append_header(ngx_http_request_t *r, ngx_str_t *name,
    ngx_str_t *value)
{
    u_char           *p;
    ngx_list_t       *headers;
    ngx_table_elt_t  *h;

    headers = &r->headers_out.headers;

    h = ngx_list_push(headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, name->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, name->data, name->len);

    h->key.data = p;
    h->key.len = name->len;

    p = ngx_pnalloc(r->pool, value->len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(p, value->data, value->len);

    h->value.data = p;
    h->value.len = value->len;
    h->hash = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_lua_add_header(lua_State *L, ngx_http_request_t *r, ngx_str_t *name,
    int index)
{
    ngx_str_t         value;
    ngx_uint_t        i;
    ngx_list_t       *headers;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header, *h;

    if (!lua_isstring(L, index) && !lua_istable(L, index)) {
        luaL_error(L, "Invalid header value");
        return NGX_ERROR;
    }

    headers = &r->headers_out.headers;
    part = &headers->part;
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

        if (h->hash == 0
            || h->key.len != name->len
            || ngx_strncasecmp(h->key.data, name->data, name->len) != 0)
        {
            continue;
        }

        h->hash = 0;
    }

    if (lua_istable(L, index)) {
        lua_pushvalue(L, index);
        lua_pushnil(L);

        while (lua_next(L, -2)) {
            lua_pushvalue(L, -2);

            value.data = (u_char *) luaL_checklstring(L, -2, &value.len);

            if (ngx_http_lua_append_header(r, name, &value) != NGX_OK) {
                return NGX_ERROR;
            }

            lua_pop(L, 2);
        }

        lua_pop(L, 1);

        return NGX_OK;
    }

    value.data = (u_char *) luaL_checklstring(L, index, &value.len);

    return ngx_http_lua_append_header(r, name, &value);
}


static void
ngx_http_lua_del_header(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_uint_t        i;
    ngx_list_t       *headers;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *header, *h;

    headers = &r->headers_out.headers;
    part = &headers->part;
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

        if (h->hash == 0
            || h->key.len != name->len
            || ngx_strncasecmp(h->key.data, name->data, name->len) != 0)
        {
            continue;
        }

        h->hash = 0;
    }
}
