#!/usr/bin/perl

# (C) Roman Arutyunyan
# (C) Dmitry Volyntsev
# (C) Nginx, Inc.

# Tests for http lua module.

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF /;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http rewrite/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    lua_include http.lua;

    lua_set $test_addr     test_addr;
    lua_set $test_method   test_method;
    lua_set $test_host     test_host;
    lua_set $test_uri      test_uri;
    lua_set $test_version  test_version;
    lua_set $test_var1     test_var1;
    lua_set $test_var2     test_var2;
    lua_set $test_var3     test_var3;
    lua_set $test_args     test_args;
    lua_set $test_arg      test_arg;
    lua_set $test_log      test_log;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        location /addr {
            return 200 $test_addr;
        }

        location /method {
            return 200 $test_method;
        }

        location /host {
            return 200 $test_host;
        }

        location /uri {
            return 200 $test_uri;
        }

        location /version {
            return 200 $test_version;
        }

        location /body {
            lua_content request_body;
        }

        location /in_file {
            client_body_in_file_only on;
            lua_content request_body;
        }

        location /status {
            lua_content status;
        }

        location /var_get {
            return 200 $test_var1;
        }

        location /var_set {
            return 200 $test_var2;
        }

        location /var_unknowe {
            return 200 $test_var3;
        }

        location /args_all {
            return 200 $test_args;
        }

        location /args_get {
            return 200 $test_arg;
        }

        location /header_in {
            lua_content header_in;
        }

        location /header_out {
            lua_content header_out;
        }

        location /header_delete {
            lua_content header_delete;
            lua_header_filter  header_filter;
        }

        location /content_length {
            lua_content content_length;
        }

        location /content_type {
            lua_content content_type;
        }

        location /content_encoding {
            lua_content content_encoding;
        }

        location /ctx {
            lua_access  ctx_access;
            lua_content ctx_content;
            lua_header_filter  ctx_header_filter;
        }

        location /empty {
            lua_content empty;
        }

        location /response {
            lua_content response;
        }

        location /not_found {
            lua_content not_found;
        }

        location /log {
            return 200 $test_log;
        }
    }
}

EOF

$t->write_file('http.lua', <<EOF);

function test_addr(r)
    return 'addr=' .. r.remote_addr
end

function test_method(r)
    return 'method=' .. r.method
end

function test_host(r)
    return 'host=' .. r.host
end

function test_uri(r)
    return 'uri=' .. r.uri
end

function test_version(r)
    return 'version=' .. r.http_version
end

function request_body(r)
    local body = r.request_body
    if (not body) then
        return r.exit(400)
    end
    r.response(body)
end

function status(r)
    r.status = 204;
    r.response("blah")
end

function test_args(r)
    local n = 0
    for _, _ in pairs(r.args) do
        n = n + 1
    end
    return 'args=' .. n
end

function test_arg(r)
    return 'arg=' .. r.args.foo
end

function test_var1(r)
    return 'variable=' .. r.vars.remote_addr
end

function test_var2(r)
    r.vars.args = "blah"
    return r.vars.args
end

function test_var3(r)
    r.vars.foo = "blahh"
    return r.vars.foo
end

function header_in(r)
    r.response('host=localhost')
end

function header_out(r)
    r.res_headers.set('Foo', {'foo1', 'foo2', 'foo3'})
    local hs = r.res_headers.get('foo')
    r.response(hs)
end

function header_delete(r)
    r.response('ok', {
        headers = {
            Foo = 'foo'
        }
    })
end

function header_filter(r)
    r.res_headers.delete('unknown')
    r.res_headers.delete('foo')
end

function content_length(r)
    if (not r.req_headers.get('Content-Length')) then
        local headers = r.res_headers
        headers.set('Content-Length', '4')
        r.response("blah")
    end
end 

function content_type(r)
    local headers = r.res_headers
    headers.set('Content-Type', 'text/xml')
    headers.set('Content-Type', '')
    headers.set('Content-Type', 'text/xml; charset=')
    headers.set('Content-Type', 'text/xml; charset=utf-8')
    headers.set('Content-Type', 'text/xml; charset="utf-8"')
    local hdr = headers.get('Content-Type')
    r.response(hdr)
end

function content_encoding(r)
    local headers = r.res_headers
    headers.set('Content-Encoding', '')
    headers.set('Content-Encoding', 'gzip')
    local hdr = headers.get('Content-Encoding')
    r.response(hdr)
end

function ctx_access(r)
    r.ctx.foo = {'a', 'b', 'c'}
end

function ctx_content(r)
    r.ctx.header = { name = 'Foo', value = 'blah' }
    local s = 'foo'
    for _, v in ipairs(r.ctx.foo) do
        s = s .. ',' .. v
    end
    r.response(s)
end

function ctx_header_filter(r)
    r.res_headers.set(r.ctx.header.name, r.ctx.header.value)
end

function response(r)
    r.response("hello", {
        status = 403,
        headers = {
            X = 'x',
            Y = 'y'
        }
    })
end

function empty(r)

end

function not_found(r)
    r.exit(404)
end

function test_log(r)
    r.log(ngx.LOG_ERR, 'SEE-THIS');
end

EOF

$t->try_run('no lua available')->plan(26);

###############################################################################


like(http_get('/addr'), qr/addr=127.0.0.1/, 'r.remote_addr');
like(http_get('/method'), qr/method=GET/, 'r.method');
like(http_get('/host'), qr/host=localhost/, 'r.host');
like(http_get('/uri'), qr/uri=\/uri/, 'r.uri');
like(http_get('/version'), qr/version=1.0/, 'r.version');
like(http_post('/body'), qr/REQ-BODY/, 'request body');
like(http_post('/in_file'), qr/400 Bad Request/, 'request body in file');
like(http_post_big('/body'), qr/200.*^(1234567890){1024}$/ms, 'big body');
like(http_get('/status'), qr/204 No Content/, 'r.status');
like(http_get('/var_get'), qr/variable=127.0.0.1/, 'r.vars get');
like(http_get('/var_set'), qr/blah/, 'r.vars set');
like(http_get('/var_unknowe'), qr/Content-Length: 0/, 'r.vars unknown');
like(http_get('/args_all?foo=12345&z=abc&c=1&d'), qr/args=3/, 'r.args count');
like(http_get('/args_get?foo=12345&z=abc'), qr/arg=12345/, 'r.args get');
like(http_get('/header_in'), qr/host=localhost/, 'r.req_headers get');
like(http_get('/header_out'), qr/foo1,foo2,foo3/, 'r.res_headers set');
like(http_get('/header_delete'), qr/ok/, 'r.res_headers delete');
like(http_get('/content_length'), qr/Content-Length: 4/,
              'r.res_headers Content-Length');
like(http_get('/content_type'), qr/text\/xml; charset=\"utf-8\"/,
              'r.res_headers Content-Type');
like(http_get('/content_encoding'), qr/gzip/,
              'r.res_headers Content-Encoding');
like(http_get('/ctx'), qr/Foo: blah.*foo,a,b,c/ms, 'r.ctx');
like(http_get('/response'), qr/hello/, 'r.response');
like(http_get('/empty'), qr/500 Internal Server Error/, 'empty');
like(http_get('/not_found'), qr/404 Not Found/, 'not found');
like(http_get('/log'), qr/200 OK/, 'r.log');

$t->stop();

ok(index($t->read_file('error.log'), 'SEE-THIS') > 0, 'log lua');

###############################################################################

sub http_post {
    my ($url, %extra) = @_;

    my $p = "POST $url HTTP/1.0" . CRLF .
        "Host: localhost" . CRLF .
        "Content-Length: 8" . CRLF .
        CRLF .
        "REQ-BODY";

    return http($p, %extra);
}

sub http_post_big {
    my ($url, %extra) = @_;

    my $p = "POST $url HTTP/1.0" . CRLF .
        "Host: localhost" . CRLF .
        "Content-Length: 10240" . CRLF .
        CRLF .
        ("1234567890" x 1024);

    return http($p, %extra);
}

###############################################################################
