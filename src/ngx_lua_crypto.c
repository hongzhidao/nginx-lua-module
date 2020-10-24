
/*
 * Copyright (C) hongzhidao
 */


#include <ngx_lua.h>
#include <ngx_md5.h>
#include <ngx_sha2.h>


typedef void (*ngx_hash_init_pt)(void *ctx);
typedef void (*ngx_hash_update_pt)(void *ctx, const void *data, size_t size);
typedef void (*ngx_hash_final_pt)(u_char *result, void *ctx);
typedef ngx_int_t (*ngx_digest_encode_pt)(ngx_pool_t *pool, ngx_str_t *dst,
    ngx_str_t *src);


typedef struct {
    ngx_str_t           name;
    size_t              size;
    ngx_hash_init_pt    init;
    ngx_hash_update_pt  update;
    ngx_hash_final_pt   final;
} ngx_hash_alg_t;


typedef struct {
    u_char              opad[64];
    union {
        ngx_sha2_t      sha2;
    } u;
    ngx_hash_alg_t     *alg;
} ngx_lua_hmac_t;


typedef struct {
    ngx_str_t             name;
    ngx_digest_encode_pt  encode;
} ngx_crypto_enc_t;


static int ngx_lua_hmac_new(lua_State *L);
static int ngx_lua_hmac_update(lua_State *L);
static int ngx_lua_hmac_digest(lua_State *L);
static int ngx_lua_hmac_gc(lua_State *L);
static int ngx_lua_hmac_tostring(lua_State *L);
static ngx_hash_alg_t *ngx_crypto_algorithm(ngx_str_t *name);
static ngx_crypto_enc_t *ngx_crypto_encoding(ngx_str_t *name);
static ngx_int_t ngx_digest_hex(ngx_pool_t *pool, ngx_str_t *dst,
    ngx_str_t *src);
static ngx_int_t ngx_digest_base64(ngx_pool_t *pool, ngx_str_t *dst,
    ngx_str_t *src);


static ngx_hash_alg_t ngx_hash_algorithms[] = {

   {
     ngx_string("md5"),
     16,
     (ngx_hash_init_pt) ngx_md5_init,
     (ngx_hash_update_pt) ngx_md5_update,
     (ngx_hash_final_pt) ngx_md5_final
   },

   { ngx_string("sha256"),
     32,
     (ngx_hash_init_pt) ngx_sha2_init,
     (ngx_hash_update_pt) ngx_sha2_update,
     (ngx_hash_final_pt) ngx_sha2_final
   },

   { ngx_null_string,
     0,
     NULL,
     NULL,
     NULL
   }
};


static ngx_crypto_enc_t ngx_encodings[] = {

   { ngx_string("hex"),
     ngx_digest_hex
   },

   { ngx_string("base64"),
     ngx_digest_base64
   },

   { ngx_null_string,
    NULL
   }
};


static const struct luaL_Reg ngx_lua_hmac_functions[] = {
    {"new", ngx_lua_hmac_new},
    {NULL, NULL}
};


static const struct luaL_Reg ngx_lua_hmac_methods[] = {
    {"update", ngx_lua_hmac_update},
    {"digest", ngx_lua_hmac_digest},
    {"__gc", ngx_lua_hmac_gc},
    {"__tostring", ngx_lua_hmac_tostring},
    {NULL, NULL},
};


#define LHMAC  "lhmac"


static int
ngx_lua_hmac_new(lua_State *L)
{
    ngx_uint_t       i;
    ngx_str_t        name, key;
    ngx_hash_alg_t  *alg;
    ngx_lua_hmac_t  *hmac;
    u_char           digest[32], key_buf[64];

    name.data = (u_char *) luaL_checklstring(L, 1, &name.len);
    key.data = (u_char *) luaL_checklstring(L, 2, &key.len);

    alg = ngx_crypto_algorithm(&name);
    if (alg == NULL) {
        return luaL_error(L, "invalid algorithm");
    }

    hmac = (ngx_lua_hmac_t *) lua_newuserdata(L, sizeof(*hmac));
    if (hmac == NULL) {
        return 0;
    }

    hmac->alg = alg;

    if (key.len > sizeof(key_buf)) {
        alg->init(&hmac->u);
        alg->update(&hmac->u, key.data, key.len);
        alg->final(digest, &hmac->u);

        memcpy(key_buf, digest, alg->size);
        ngx_memzero(key_buf + alg->size, sizeof(key_buf) - alg->size);

    } else {
        memcpy(key_buf, key.data, key.len);
        ngx_memzero(key_buf + key.len, sizeof(key_buf) - key.len);
    }

    for (i = 0; i < 64; i++) {
        hmac->opad[i] = key_buf[i] ^ 0x5c;
    }

    for (i = 0; i < 64; i++) {
         key_buf[i] ^= 0x36;
    }

    alg->init(&hmac->u);
    alg->update(&hmac->u, key_buf, 64);

    luaL_getmetatable(L, LHMAC);
    lua_setmetatable(L, -2);

    return 1;
}


static ngx_hash_alg_t *
ngx_crypto_algorithm(ngx_str_t *name)
{
    ngx_hash_alg_t  *e;

    for (e = &ngx_hash_algorithms[0]; e->name.len != 0; e++) {
        if (e->name.len == name->len
            && ngx_strncmp(e->name.data, name->data, name->len) == 0)
        {
            return e;
        }
    }

    return NULL;
}


static int
ngx_lua_hmac_update(lua_State *L)
{
    size_t           len;
    u_char          *data;
    ngx_lua_hmac_t  *hmac;

    hmac = (ngx_lua_hmac_t *) luaL_checkudata(L, 1, LHMAC);
    data = (u_char *) luaL_checklstring(L, 2, &len);

    hmac->alg->update(&hmac->u, data, len);

    return 0;
}


static int
ngx_lua_hmac_digest(lua_State *L)
{
    ngx_str_t          str, dst, name;
    ngx_lua_ctx_t     *lua;
    ngx_hash_alg_t    *alg;
    ngx_lua_hmac_t    *hmac;
    ngx_crypto_enc_t  *enc;
    u_char             hash1[32], digest[32];

    lua = ngx_lua_get_ext(L);

    hmac = (ngx_lua_hmac_t *) luaL_checkudata(L, 1, LHMAC);
    name.data = (u_char *) luaL_checklstring(L, 2, &name.len);

    alg = hmac->alg;

    enc = ngx_crypto_encoding(&name);
    if (enc == NULL) {
        return luaL_error(L, "invalid enc");
    }

    alg->final(hash1, &hmac->u);

    alg->init(&hmac->u);
    alg->update(&hmac->u, hmac->opad, 64);
    alg->update(&hmac->u, hash1, alg->size);
    alg->final(digest, &hmac->u);
    hmac->alg = NULL;

    str.data = digest;
    str.len = alg->size;

    dst.len = ngx_base64_encoded_length(str.len);
    dst.data = ngx_pcalloc(lua->pool, dst.len);
    
    if (dst.data == NULL) {
        return 0;
    }

    if (enc->encode(lua->pool, &dst, &str) != NGX_OK) {
        return 0;
    }

    lua_pushlstring(L, (const char *) dst.data, dst.len);

    return 1;
}


static ngx_int_t
ngx_digest_hex(ngx_pool_t *pool, ngx_str_t *dst, ngx_str_t *src)
{
    dst->len = 32;
    dst->data = ngx_pcalloc(pool, dst->len);

    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(dst->data, src->data, 16);

    return NGX_OK;
}


static ngx_int_t
ngx_digest_base64(ngx_pool_t *pool, ngx_str_t *dst, ngx_str_t *src)
{
    dst->len = ngx_base64_encoded_length(src->len);
    dst->data = ngx_pcalloc(pool, dst->len);

    if (dst->data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64(dst, src);

    return NGX_OK;
}


static ngx_crypto_enc_t *
ngx_crypto_encoding(ngx_str_t *name)
{
    ngx_crypto_enc_t  *e;

    for (e = &ngx_encodings[0]; e->name.len != 0; e++) {
        if (e->name.len == name->len
            && ngx_strncmp(e->name.data, name->data, name->len) == 0)
        {
            return e;
        }
    }

    return NULL;
}


static int
ngx_lua_hmac_gc(lua_State *L)
{
    ngx_lua_hmac_t  *hmac;

    hmac = (ngx_lua_hmac_t *) luaL_checkudata(L, 1, LHMAC);

    (void) hmac;

    return 0;
}


static int
ngx_lua_hmac_tostring(lua_State *L)
{
    ngx_lua_hmac_t  *hmac;

    hmac = (ngx_lua_hmac_t *) luaL_checkudata(L, 1, LHMAC);

    (void) hmac;

    //lua_pushfstring(L, "test");

    return 1;
}


void
ngx_lua_crypto_register(lua_State *L)
{
    luaL_newmetatable(L, LHMAC);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, ngx_lua_hmac_methods, 0);
    lua_pop(L, 1);

    luaL_newlib(L, ngx_lua_hmac_functions);
    lua_setfield(L, -2, "hmac");
}
