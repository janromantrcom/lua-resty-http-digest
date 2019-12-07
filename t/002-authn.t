use t::Common 'no_plan';

no_shuffle();
run_tests();

__DATA__

=== save nonce in redis and wait for timeout
--- config
location = /t {
    content_by_lua_block {
        local suite = require 't.suite'
        local red, err = suite.get_redis_conn()
        if err then
            suite.die_here(500, 'connect redis: ' .. err)
        end

        local http_digest = require 'resty.http_digest'
        local t = http_digest:new({
            get_password = suite.get_password,
            auth_timeout = 1,
            nonce_age = 1,
        })
        t:authenticate()
        local auth = suite.parse_www_authn_header()
        local nonce = auth.nonce
        local res, err = red:get(suite.make_redis_key(nonce))
        if res == ngx.null or err then
            suite.die_here(500, 'nonce not found')
        end
        ngx.sleep(1)
        res, err = red:get(suite.make_redis_key(nonce))
        if res ~= ngx.null or err then
            suite.die_here(500, 'expired nonce still exists')
        end
        ngx.say('OK')
    }
}
--- request
GET /t
--- response_headers_like
WWW-Authenticate: Digest .*
--- error_code: 401
--- response_body
OK
--- timeout: 2


=== authn
--- config
location = /t {
    content_by_lua_block {
        local suite = require 't.suite'
        local red, err = suite.get_redis_conn()
        if err then
            suite.die_here(500, 'connect redis: ' .. err)
        end

        local http_digest = require 'resty.http_digest'
        local t = http_digest:new({
            get_password = suite.get_password,
            auth_timeout = 5,
            nonce_age = 5,
        })
        t:authenticate()
        local auth = suite.parse_www_authn_header()

        local res = red:get(suite.make_redis_key(auth.nonce))
        if res ~= '0' then
            suite.die_here(500, 'wrong nc: expect 0, got: ' .. res)
        end

        local resp = t.calc_response(ngx.md5, 'foo', auth.realm, 'foo', 'GET', '/t', auth.nonce, '00000001', 'zxcqwe', auth.qop)
        ngx.req.set_header('Authorization', string.format('Digest username=foo, uri=/t, cnonce="zxcqwe", nc=00000001, response=%s, realm=%s, qop=%s, nonce=%s', resp, auth.realm, auth.qop, auth.nonce))
        local _, err = t:authenticate()
        if err then
            suite.die_here(500, err)
        end

        local res = red:get(suite.make_redis_key(auth.nonce))
        if res ~= '1' then
            suite.die_here(500, 'wrong nc: expect 1, got: ' .. res)
        end
        ngx.status = 200
        ngx.say('OK')
    }
}
--- request
GET /t
--- response_body
OK


=== prohibit same nc
--- config
location = /t {
    content_by_lua_block {
        local suite = require 't.suite'
        local red, err = suite.get_redis_conn()
        if err then
            suite.die_here(500, 'connect redis: ' .. err)
        end

        local http_digest = require 'resty.http_digest'
        local t = http_digest:new({
            get_password = suite.get_password,
            auth_timeout = 5,
            nonce_age = 5,
        })
        t:authenticate()
        local auth = suite.parse_www_authn_header()
        local resp = t.calc_response(ngx.md5, 'foo', auth.realm, 'foo', 'GET', '/t', auth.nonce, '00000001', 'zxcqwe', auth.qop)
        ngx.req.set_header('Authorization', string.format('Digest username=foo, uri=/t, cnonce="zxcqwe", nc=00000001, response=%s, realm=%s, qop=%s, nonce=%s', resp, auth.realm, auth.qop, auth.nonce))
        local _, err = t:authenticate()
        if err then
            suite.die_here(500, err)
        end

        local _, err = t:authenticate()
        if not err then
            suite.die_here(500, 'expect error on same nc')
        end

        ngx.say('OK')
    }
}
--- request
GET /t
--- error_code: 403
--- response_body
OK


=== prohibit stale nc
--- config
location = /t {
    content_by_lua_block {
        local suite = require 't.suite'
        local red, err = suite.get_redis_conn()
        if err then
            suite.die_here(500, 'connect redis: ' .. err)
        end

        local http_digest = require 'resty.http_digest'
        local t = http_digest:new({
            get_password = suite.get_password,
            auth_timeout = 5,
            nonce_age = 5,
            max_replays = 1,
        })

        t:authenticate()

        local auth, resp
        auth = suite.parse_www_authn_header()
        resp = t.calc_response(ngx.md5, 'foo', auth.realm, 'foo', 'GET', '/t', auth.nonce, '00000001', 'zxcqwe', auth.qop)
        ngx.req.set_header('Authorization', string.format('Digest username=foo, uri=/t, cnonce="zxcqwe", nc=00000001, response=%s, realm=%s, qop=%s, nonce=%s', resp, auth.realm, auth.qop, auth.nonce))
        local _, err = t:authenticate()
        if err then
            suite.die_here(500, err)
        end

        auth = suite.parse_www_authn_header()
        resp = t.calc_response(ngx.md5, 'foo', auth.realm, 'foo', 'GET', '/t', auth.nonce, '00000002', 'zxcqwe', auth.qop)
        ngx.req.set_header('Authorization', string.format('Digest username=foo, uri=/t, cnonce="zxcqwe", nc=00000002, response=%s, realm=%s, qop=%s, nonce=%s', resp, auth.realm, auth.qop, auth.nonce))
        auth, err = t:authenticate()
        if not err then
            suite.die_here(500, 'expect error on stale nc: ' .. auth.nonce)
        end

        auth = suite.parse_www_authn_header()
        ngx.say(auth.stale)
    }
}
--- request
GET /t
--- error_code: 401
--- response_body
true
