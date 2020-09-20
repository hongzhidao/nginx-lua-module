
/*
 * Copyright (C) Jedo Hong
 * Copyright (C) <hongzhidao@gmail.com>
 */


#include <ngx_http_lua.h>


void
ngx_http_lua_register_global(lua_State *L)
{
    lua_createtable(L, 0, 100);

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

    lua_setglobal(L, "ngx");
}
