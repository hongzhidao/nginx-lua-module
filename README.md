# nginx-http-lua-module
The module allows using lua in nginx. 

Compatibility
=============

- nginx version >= 1.14+
- lua version >= 5.3+
- tested on recent Linux

Build
=====

Configuring nginx with the module.

    $ ./configure --add-module=/path/to/nginx-http-lua-module
    
Directives
==========

- ``lua_shm`` (http)
- ``lua_include`` (http)
- ``lua_set`` (http)
- ``lua_access`` (http|server|location)
- ``lua_content`` (http|server|location)

Apis
====
- ``ngx.method`` the client HTTP request method, readonly.
- ``ngx.uri`` the client HTTP request uri, readonly.
- ``ngx.http_version`` the client HTTP request version, readonly.
- ``ngx.remote_addr`` the client ip, readonly.
- ``ngx.status`` the client HTTP response status.
- ``ngx.arg{}`` the client HTTP request args, readonly.
- ``ngx.header{}`` the client HTTP request header, readonly.
- ``ngx.headers{}`` the client HTTP response header.
- ``ngx.request_body`` the client HTTP request body.
- ``ngx.var{}``
- ``ngx.log(msg)``
- ``ngx.warn(msg)``
- ``ngx.error(msg)``
- ``ngx.read_body()`` call this first while use ngx.request_body before content phase. 
- ``ngx.finish(status, desc``)
- ``ngx.shm.x:set(k, ...)``
- ``ngx.shm.x:get(k, ...)``
- ``ngx.shm.x:del(k, ...)``
- ``ngx.shm.x:has(k, ...)``
- ``ngx.shm.x:keys(k, ...)``


Example
=======

nginx.conf
```

events {}

http {

    lua_shm  test 1M;
    lua_include  http.lua;
    lua_set $foo  foo;

    server {
        listen 8000;

        location / {
            lua_access  access1;
            lua_content  content1;
        }

        location /test {
            lua_access  access2;
        }
    }
}
```

http.lua
```

package.path = package.path .. ";/usr/local/nginx/lua/?.lua;";
package.cpath = package.cpath .. ";/usr/local/nginx/lua/?.so;";


function foo()
    return "This is a variable";
end


function access1()
    local shm = ngx.shm.test;

    shm:set("k1", "k1's val");
    shm:set("k2", "k2's val");
    shm:set("k3", "k3's val");
    
    ngx.read_body();
    local body = ngx.request_body;
end


function content1()
    local shm = ngx.shm.test;

    local arg = ngx.arg.x or "arg x";
    local uri = ngx.uri;
    local hi = ngx.header["Accept-Language"] or "header accept language";
    local body = ngx.request_body or "body";

    local k1 = shm:get("k1") or "not";
    local keys = shm:keys();
    local ks = keys[0] .. " " .. keys[1] .. " " .. keys[2];

    local var = ngx.var.foo;

    local html = "<html><head><title>nginx lua module</title></head><body>";

    local content = "arg: " .. arg .. "<br>"
                    .. "uri: " .. uri .. "<br>"
                    .. "header: " .. hi .. "<br>"
                    .. "body: " .. body .. "<br>"
                    .. "shm k1: " .. k1 .. "<br>"
                    .. "shm keys: " .. ks .. "<br>"
                    .. "var: " .. var .. "<br>";

    html = html .. content .. "</body></html>";

    ngx.headers["Content-Type"] = "text/html";

    ngx.finish(200, html);
end


function access2()
    local shm = ngx.shm.test;

    local data = [==[
{
    "glossary": {
        "version": 1001,
        "active": true,
        "title": "example glossary",
        "GlossDiv": {
            "title": "S",
            "GlossList": {
                "GlossEntry": {
                    "ID": "SGML",
                    "SortAs": "SGML",
                    "GlossTerm": "Standard Generalized Markup Language",
                    "Acronym": "SGML",
                    "Abbrev": "ISO 8879:1986",
                    "GlossDef": {
                        "para": "A meta-markup language, used to create markup languages such as DocBook.",
                        "GlossSeeAlso": "GMLXML"
                    },
                    "GlossSee": "markup"
                }
            }
        }
    }
}
]==];

    -- You should put cjson.so in /usr/local/nginx/lua directory first.
    local cjson = require("cjson.safe");

    local table = cjson.decode(data);
    shm:set("test", table);

    local s = shm:get("test", "glossary", "GlossDiv", "GlossList", "GlossEntry", "GlossDef", "para");

    ngx.finish(200, s);
end
```

Community
=========

Author: Jedo Hong 

Contact: hongzhidao@gmail.com

All feedback welcome. Thanks.

Inspired From
-------------
njs: https://github.com/nginx/njs

python: https://github.com/arut/nginx-python-module
