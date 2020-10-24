# nginx-lua-module
Embedded offical Lua language into NGINX.

Compatibility
=============

- NGINX 1.16.0+
- Lua 5.3.0+
- Linux

Build
=====

Configuring nginx with the module.

    $ ./configure --add-module=/path/to/nginx-lua-module
    
Directives
==========

- ``lua_include`` (http)
- ``lua_set`` (http)
- ``lua_access`` (http|server|location)
- ``lua_content`` (http|server|location)
- ``lua_header_filter`` (http|server|location)

request object
====
- ``r.uri`` the client HTTP request uri, readonly.
- ``r.host`` the same to the variable $host.
- ``r.method`` the client HTTP request method, readonly.
- ``r.http_version`` the client HTTP request version, readonly.
- ``r.remote_addr`` the client ip, readonly.
- ``r.request_body`` the client HTTP request body.
- ``r.status`` the client HTTP response status, read|write.
- ``r.args{}`` the client HTTP request args, readonly.
- ``r.vars{}`` read|write.
- ``r.log(level, msg)``
- ``r.req_headers`` the client HTTP request headers.
- ``r.req_headers.get(name)``
- ``r.res_headers`` the client HTTP response headers.
- ``r.res_headers.get(name)``
- ``r.res_headers.set(name, string|array)``
- ``r.response(text, { status = status, headers = {name = string|array, ...}})``
- ``r.exit(status)``

ngx object
==========
Log error levels  
- ``ngx.LOG_EMERG``
- ``ngx.LOG_ALERT``
- ``ngx.LOG_CRIT``
- ``ngx.LOG_ERR``
- ``ngx.LOG_WARN``
- ``ngx.LOG_NOTICE``
- ``ngx.LOG_INFO``
- ``ngx.LOG_DEBUG``
- ``ngx.log(level, msg)``


Example
=======

nginx.conf
```
events {}

http {
    lua_include  http.lua;
    lua_set  $foo foo;

    server {
        listen 8000;

        lua_header_filter  header_filter;

        location / {
            lua_access   http_access;
            lua_content  http_content;
        }

        location /hello {
            lua_content  hello;
        }

        location /remote_addr {
            return  200 $foo;
        }
    }
}
```

http.lua
```
package.path = package.path .. ";/usr/local/nginx/lua/?.lua;";
package.cpath = package.cpath .. ";/usr/local/nginx/lua/?.so;";


function foo(r)
    return "remote addr=" .. r.remote_addr
end


function hello(r)
    r.response("hello lua.")
end


function http_access(r)
    if (r.remote_addr == '1.1.1.1') then
        r.exit(403)
    end

    r.ctx.foo = 'blah'
end


function http_content(r)
    local nargs = #r.args
    local req_headers = r.req_headers
    local body = r.request_body or "blah";

    local text = "<html><head><title>nginx lua module</title></head><body>";
    local content = "args: " .. nargs .. "<br>"
                    .. "uri: " .. r.uri .. "<br>"
                    .. "host: " .. req_headers.get('Host') .. "<br>"
                    .. "body: " .. body .. "<br>"
                    .. "var: " .. r.vars.remote_addr .. "<br>"
                    .. "foo: " .. r.ctx.foo .. "<br>"
    text = text .. content .. "</body></html>";

    local headers = {
        ["Content-Type"] = 'text/html'
    }

    r.response(text, {
        status = 200,
        headers = headers
    });
end


function header_filter(r)
    r.status = 204
end
```

Community
=========
Author: 洪志道
Contact: hongzhidao@gmail.com  
Feedbacks are welcome. Have fun :)

Inspired From
-------------
njs: https://github.com/nginx/njs  
python: https://github.com/arut/nginx-python-module
