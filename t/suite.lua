local resty_redis = require 'resty.redis'
local resty_sha256 = require 'resty.sha256'
local resty_str = require "resty.string"

return {
    get_redis_conn = function(host, port, db)
        local red = resty_redis:new()
        red:set_timeout(1000)
        local ok, err = red:connect(host or '127.0.0.1', port or 6379)
        if not ok then
            return nil, err
        end
        red:select(db or '0')
        return red
    end,

    make_redis_key = function(nonce)
        return 'digest-nonce-v1:' .. nonce
    end,

    parse_www_authn_header = function()
        local hdr = ngx.resp.get_headers()['www-authenticate']
        local auth_str = string.match(hdr, 'Digest%s+(.+)')
        if auth_str == nil then
            return nil, 'invalid header'
        end
        local auth = {}
        for k, v in string.gmatch(auth_str, '(%w+)="?([%w%%%-./=:;_?&+]+)"?') do
            auth[k] = v
        end
        return auth
    end,

    get_password = function(name) return name end,

    sha256 = function(s)
        local h = resty_sha256:new()
        h:update(s)
        return resty_str.to_hex(h:final())
    end,

    die_here = function (status, msg)
        ngx.status = status
        ngx.log(ngx.ERR, msg)
        ngx.exit(status)
    end,
}
