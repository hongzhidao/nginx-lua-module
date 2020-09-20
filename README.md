# nginx-http-lua-module
The module allows using lua in nginx. 

Compatibility
=============

- nginx version >= 1.14+
- lua version >= 5.3+
- tested on Linux

Build
=====

Configuring nginx with the module.

    $ ./configure --add-module=/path/to/nginx-http-lua-module
    
Directives
==========

- ``lua_include`` (http)
- ``lua_set`` (http)
- ``lua_access`` (http|server|location)
- ``lua_content`` (http|server|location)
- ``lua_header_filter`` (http|server|location)

HTTP Request
====
- ``r.method`` the client HTTP request method, readonly.
- ``r.uri`` the client HTTP request uri, readonly.
- ``r.http_version`` the client HTTP request version, readonly.
- ``r.remote_addr`` the client ip, readonly.
- ``r.status`` the client HTTP response status, readonly.
- ``r.arg{}`` the client HTTP request args, readonly.
- ``r.request_body`` the client HTTP request body.
- ``r.var{}``
- ``r.log(msg)``
- ``r.warn(msg)``
- ``r.error(msg)``
- ``r.header_in(name)`` the client HTTP request header, readonly.
- ``r.header_out(name[, value])`` the client HTTP response header.
- ``r.read_body()`` call this first while use r.request_body before content phase. 
- ``r.exit(status, desc``)


Example
=======

nginx.conf
```

events {}

http {
    lua_include  http.lua;
    lua_set $foo  foo;
    lua_header_filter  header_filter;

    server {
        listen 8000;

        location / {
            lua_access  access1;
            lua_content  content1;
        }
    }
}
```

http.lua
```

package.path = package.path .. ";/usr/local/nginx/lua/?.lua;";
package.cpath = package.cpath .. ";/usr/local/nginx/lua/?.so;";


function foo(r)
    return "This is a variable";
end


function header_filter(r)
    r.header_out('X-Test', "test test test");
end


function access1(r)
    r.read_body();
    local body = r.request_body;
end


function content1(r)
    local arg = r.arg.x or "arg x";
    local uri = r.uri;
    local hi = r.header_in("Accept-Language") or "header accept language";
    local body = r.request_body or "body";

    local var = r.var.foo;

    local html = "<html><head><title>nginx lua module</title></head><body>";

    local content = "arg: " .. arg .. "<br>"
                    .. "uri: " .. uri .. "<br>"
                    .. "header: " .. hi .. "<br>"
                    .. "body: " .. body .. "<br>"
                    .. "var: " .. var .. "<br>";

    html = html .. content .. "</body></html>";

    r.header_out("Content-Type", "text/html");

    r.exit(200, html);
end
```

Community
=========
Author: Jedo Hong  
Contact: hongzhidao@gmail.com  
Feedbacks are welcome. Enjoy it.

Inspired From
-------------
njs: https://github.com/nginx/njs  
python: https://github.com/arut/nginx-python-module
