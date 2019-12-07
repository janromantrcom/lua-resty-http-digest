use t::Common 'no_plan';

no_long_string();
run_tests();

__DATA__

=== valid authorization header
--- config
location = /t {
    content_by_lua_block {
        local suite = require 't.suite'
        local http_digest = require 'resty.http_digest'
        local auth, err = http_digest.parse_authz_header(ngx.var.http_authorization)
        if err then
            suite.die_here(500, err)
        end
        local got = {auth.response, auth.realm, auth.algorithm, auth.username, auth.uri, auth.qop, auth.nonce, auth.cnonce, auth.nc}
        ngx.say(table.concat(got, ':'))
    }
}
--- request
GET /t
--- more_headers
Authorization: Digest response="r" realm="no_space" algorithm=MD5 username="foo" uri="/t?q=z&w=c+%251" qop="auth" nonce="z" cnonce="x" nc=00000001
--- response_body
r:no_space:MD5:foo:/t?q=z&w=c+%251:auth:z:x:00000001


=== invalid authorization header: missing field
--- config
location = /t {
    content_by_lua_block {
        local suite = require 't.suite'
        local http_digest = require 'resty.http_digest'
        local _, err = http_digest.parse_authz_header(ngx.var.http_authorization)
        if not err then
            suite.die_here(500, 'expect error in parsing authz header')
        end
        ngx.say(err)
    }
}
--- request
GET /t
--- more_headers
Authorization: Digest realm="no_space" algorithm=MD5 username="foo" uri="/t?q=z&w=c+%251" qop="auth" cnonce="x" nc=00000001
--- response_body_like
missing field.*
--- error_log


=== compute response: md5
--- config
location = /t {
    content_by_lua_block {
        local suite = require 't.suite'
        local http_digest = require 'resty.http_digest'
        ngx.say(http_digest.calc_response(ngx.md5, 'foo', 'localhost', 'root', 'GET', '/t','bda68fMTU3NTcwNzgzMC40NDU', '00000001', 'NDk0ZTNhMDgyZjIzZjA3OTk3Y2QxNjc5ZDlkOGYyZDQ=', 'auth'))
    }
}
--- request
GET /t
--- response_body
26e01f1ae944e1d2098c09fe64a06d8e


=== compute response: sha256
--- config
location = /t {
    content_by_lua_block {
        local suite = require 't.suite'
        local http_digest = require 'resty.http_digest'
        ngx.say(http_digest.calc_response(suite.sha256, 'foo', 'localhost', 'root', 'GET', '/t', 'ckFx7v8uwzMrxCM322ER', '00000002', 'S5tAVb0hagwz1H7WmM+hIUTXX8l4', 'auth'))
    }
}
--- request
GET /t
--- response_body
dd74b1a2cc2d03cf577830efdbbc2be307edcad27715a31c910ad75594ec5191
