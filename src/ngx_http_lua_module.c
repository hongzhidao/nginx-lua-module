
/*
 * Copyright (C) Jedo Hong
 */


#include <ngx_http_lua.h>


static void ngx_http_lua_content_event_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_lua_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_lua_init(ngx_conf_t *cf);
static void *ngx_http_lua_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_lua_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_lua_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_lua_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_lua_set(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_lua_content(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_lua_commands[] = {

    { ngx_string("lua_include"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_lua_main_conf_t, file),
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
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;


static ngx_int_t
ngx_http_lua_header_filter(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_http_lua_loc_conf_t     *flcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http lua header filter handler");

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    if (flcf->header_filter.len == 0) {
        return ngx_http_next_header_filter(r);
    }

    /* Async operations is not allowed in header filter. */

    rc = ngx_http_lua_eval(r, &flcf->header_filter, NULL);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    /* NGX_DECLINED, NGX_OK */

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_lua_access_handler(ngx_http_request_t *r)
{
    ngx_int_t                     rc;
    ngx_http_lua_loc_conf_t      *llcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http lua access handler");

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    if (llcf->access.len == 0) {
        return NGX_DECLINED;
    }

    rc = ngx_http_lua_resume(r, &llcf->access, r->connection->write);

    if (rc == NGX_OK && r->header_sent) {
        return NGX_HTTP_OK;
    }

    /* NGX_OK, NGX_AGAIN, NGX_DECLINED, NGX_ERROR, NGX_HTTP_... */

    return rc;
}


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
    ngx_http_lua_ctx_t           *ctx;
    ngx_http_lua_loc_conf_t      *llcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http lua content event handler");

    llcf = ngx_http_get_module_loc_conf(r, ngx_http_lua_module);

    rc = ngx_http_lua_resume(r, &llcf->content, r->connection->write);

    if (rc == NGX_AGAIN) {
        r->write_event_handler = ngx_http_lua_content_event_handler;
        return;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);

    ngx_http_finalize_request(r, ctx->status);
}


static ngx_int_t
ngx_http_lua_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_str_t  *func = (ngx_str_t *) data;

    ngx_int_t     rc;
    ngx_str_t     result;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http lua variable handler");

    rc = ngx_http_lua_eval(r, func, &result);
    
    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        v->not_found = 1;
        return NGX_OK;
    }
    
    v->len = result.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = result.data; 

    return NGX_OK;
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

    func = ngx_palloc(cf->pool, sizeof(ngx_str_t));
    if (func == NULL) {
        return NGX_CONF_ERROR;
    }

    *func = value[2];

    v->get_handler = ngx_http_lua_variable;
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
