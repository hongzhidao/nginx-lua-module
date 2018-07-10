# nginx-http-lua-module
The module allows using lua in nginx. 

Compatibility
=============

- nginx version >= 1.14+
- lua version >= 5.3+
- tested on recent Linux

Build
=====

Configuring nginx with the module::

    $ ./configure --add-module=/path/to/nginx-http-lua-module

Examples
========

example1
-----

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
            lua_access  access;
            lua_content  content;
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

function access()
    local shm = ngx.shm.test;

    shm:set("k1", "k1's val");
    shm:set("k2", "k2's val");
    shm:set("k3", "k3's val");
end

function content()
    local shm = ngx.shm.test;

    local arg = ngx.arg.x or "arg x";
    local uri = ngx.uri;
    local hi = ngx.header["Accept-Language"] or "header accept language";

    local k1 = shm:get("k1") or "not";
    local keys = shm:keys();
    local ks = keys[0] .. " " .. keys[1] .. " " .. keys[2];

    local var = ngx.var.foo;

    local html = "<html><head><title>nginx lua module</title></head><body>";

    local content = "arg: " .. arg .. "<br>"
                    .. "uri: " .. uri .. "<br>"
                    .. "header: " .. hi .. "<br>"
                    .. "shm k1: " .. k1 .. "<br>"
                    .. "shm keys: " .. ks .. "<br>"
                    .. "var: " .. var .. "<br>";

    html = html .. content .. "</body></html>";

    ngx.headers["Content-Type"] = "text/html";

    ngx.finish(200, html);
end
```

Community
=========
All feedback welcome. Thanks.

Author: Jedo Hong 

Email: hongzhidao@gmail.com
