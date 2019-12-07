-- Copyright (C) Jian Zeng (knight42)

local pairs = pairs
local tonumber = tonumber
local str_match = string.match
local str_gmatch = string.gmatch
local encode_base64 = ngx.encode_base64
local ngx_now = ngx.now
local md5 = ngx.md5
local null = ngx.null
local concat = table.concat

-- https://github.com/openresty/lua-resty-string
local resty_str = require "resty.string"
local resty_random = require "resty.random"
local random_bytes = resty_random.bytes
local to_hex = resty_str.to_hex

local resty_sha256 = require "resty.sha256"

-- https://github.com/openresty/lua-resty-redis
local resty_redis = require "resty.redis"

local MD5 = 'MD5'
local SHA256 = 'SHA-256'

local HTTP_OK = ngx.HTTP_OK
local HTTP_BAD_REQUEST = ngx.HTTP_BAD_REQUEST
local HTTP_UNAUTHORIZED = ngx.HTTP_UNAUTHORIZED
local HTTP_FORBIDDEN = ngx.HTTP_FORBIDDEN
local HTTP_INTERNAL_SERVER_ERROR = ngx.HTTP_INTERNAL_SERVER_ERROR

local _M = {
    _VERSION = '0.0.1',
    MD5 = MD5,
    SHA256 = SHA256,
}
local mt = { __index = _M }

local function sha256(s)
    local h = resty_sha256:new()
    h:update(s)
    return to_hex(h:final())
end

local function make_nonce()
    return to_hex(random_bytes(3)) .. encode_base64(ngx_now(), true)
end

local function get_redis_conn(host, port, db, timeout)
    local red = resty_redis:new()
    red:set_timeout(timeout or 1000) -- 1sec
    local ok, err = red:connect(host, port)
    if not ok then
        return nil, err
    end
    red:select(db)
    return red
end

local function is_null(v)
    return v == null or v == nil
end

local function log(lvl, msg)
    ngx.log(lvl, 'digest-auth: ' .. msg)
end

local function parse_authz_header(hdr)
    local auth_str = str_match(hdr, 'Digest%s+(.+)')
    if auth_str == nil then
        return nil, 'invalid authorization header'
    end
    local auth = {}
    -- `%` and `-` has special meaning in lua pattern
    -- %% -> %
    -- %- -> -
    for k, v in str_gmatch(auth_str, '(%w+)="?([%w%%%-./=:;_?&+]+)"?') do
        auth[k] = v
    end
    return auth
end
_M.parse_authz_header = parse_authz_header

local function make_digest_challenge(t)
    local challenge = 'Digest '
    for key, val in pairs(t) do
        if key == 'algorithm' or key == 'stale' then
            -- not quoted
            challenge = challenge .. key .. '=' .. tostring(val) .. ', '
        else
            challenge = challenge .. key .. '="' .. tostring(val) .. '", '
        end
    end
    return challenge .. 'qop="auth", opaque="session"'
end

local function calc_response(get_hash, username, realm, password, method, uri, nonce, nc, cnonce, qop)
    local ha1 = get_hash(concat({username, realm, password}, ':'))
    local ha2 = get_hash(method .. ':' .. uri)
    return get_hash(concat({ha1, nonce, nc, cnonce, qop, ha2}, ':'))
end
_M.calc_response = calc_response

local function make_redis_key(nonce)
    return 'digest-nonce-v1:' .. nonce
end

function _M.new(_, opts)
    if opts.get_password == nil then
        return nil, 'get_password is required'
    end
    local get_hash
    local algo = opts.algorithm or MD5
    if algo == MD5 then
        get_hash = md5
    elseif algo == SHA256 then
        get_hash = sha256
    else
        return nil, 'unknown algorithm: ' .. algo
    end
    if not opts.redis then
        opts.redis = {}
    end
    local t = {
        get_password = opts.get_password,
        realm = opts.realm or ngx.var.http_host,
        nonce_age = opts.nonce_age or 60,
        auth_timeout = opts.auth_timeout or 60,
        max_replays = opts.max_replays or 20,
        algo = algo,
        get_hash = get_hash,

        redis_db = opts.redis.db or '0',
        redis_host = opts.redis.host or '127.0.0.1',
        redis_port = opts.redis.port or 6379,
        redis_timeout = opts.redis.timeout or 1000,
        redis_max_idle_timeout = opts.redis.max_idle_timeout,
        redis_pool_size = opts.redis.pool_size,
    }
    return setmetatable(t, mt)
end

function _M:verify(auth)
    local method = ngx.req.get_method()
    local uri = auth.uri
    local username = auth.username
    local realm = auth.realm
    local nonce = auth.nonce
    local cnonce = auth.cnonce
    local qop = auth.qop
    local nc = auth.nc
    local nc_num = tonumber(nc, 16)
    local response = auth.response
    local algorithm = auth.algorithm or MD5
    local password, err = self.get_password(username)
    if err then
        log(ngx.ERR, 'get password: ' .. username .. ': ' .. err)
        return HTTP_FORBIDDEN, 'cannot get password'
    end

    if nc == nil or nc_num == nil then
        return HTTP_FORBIDDEN, 'invalid nc' .. auth.nc
    end
    if ngx.var.request_uri ~= uri then
        -- return 400 if uri mismatched according to https://tools.ietf.org/html/rfc7616#section-3.4.6
        return HTTP_BAD_REQUEST, 'wrong uri: ' .. uri
    end
    if qop ~= 'auth' then
        return HTTP_FORBIDDEN, 'wrong qop: ' .. qop
    end
    if algorithm ~= self.algo then
        return HTTP_FORBIDDEN, 'wrong algorithm: ' .. algorithm
    end

    local expected_resp = calc_response(self.get_hash, username, realm, password, method, uri, nonce, nc, cnonce, qop)
    if expected_resp ~= response then
        return HTTP_FORBIDDEN, 'invalid response'
    end

    local red
    red, err = get_redis_conn(self.redis_host, self.redis_port, self.redis_db, self.redis_timeout)
    if red == nil then
        log(ngx.ERR, 'connect to redis: ' .. err)
        return HTTP_INTERNAL_SERVER_ERROR, 'failed to connect to redis'
    end
    local key = make_redis_key(nonce)
    local val
    val, err = red:get(key)
    if err then
        log(ngx.ERR, 'redis get key: ' .. nonce .. ': ' .. err)
        return HTTP_INTERNAL_SERVER_ERROR, 'faield to get key from redis'
    end
    if is_null(val) then
        return HTTP_UNAUTHORIZED, 'expired nonce'
    end
    local cur_nc = tonumber(val)
    if cur_nc == nil then
        log(ngx.ERR, 'invalid nc saved in redis: ' .. val)
        return HTTP_INTERNAL_SERVER_ERROR, 'unknown nc saved in redis'
    end
    if cur_nc >= self.max_replays then
        return HTTP_UNAUTHORIZED, 'stale nonce'
    end
    if cur_nc < nc_num then
        red:multi()
        red:incr(key)
        red:expire(key, self.nonce_age)
        local _, exec_err = red:exec()
        if not exec_err then
            red:set_keepalive(self.redis_max_idle_timeout, self.redis_pool_size)
        else
            log(ngx.ERR, 'redis exec: ' .. exec_err)
        end
    else
        log(ngx.WARN, 'invalid nc: ' .. nc .. ' is not greater than ' .. val)
        return HTTP_FORBIDDEN, 'invalid nc: ' .. nc
    end
    return HTTP_OK
end

function _M:set_challenge(stale)
    local realm = self.realm
    local nonce = make_nonce()
    ngx.header['WWW-Authenticate'] = make_digest_challenge({
        realm = realm,
        algorithm = self.algo,
        nonce = nonce,
        stale = stale,
    })
    local red, err = get_redis_conn(self.redis_host, self.redis_port, self.redis_db, self.redis_timeout)
    if red == nil then
        log(ngx.ERR, 'connect to redis: ' .. err)
        return err
    end
    local key = make_redis_key(nonce)
    red:multi()
    red:set(key, '0')
    red:expire(key, self.auth_timeout)
    local _, exec_err = red:exec()
    if not exec_err then
        red:set_keepalive(self.redis_max_idle_timeout, self.redis_pool_size)
    else
        log(ngx.ERR, 'redis exec: ' .. exec_err)
        return exec_err
    end
end

local function _challenge(self, stale)
    local err = self:set_challenge(stale)
    if err then
        ngx.status = HTTP_INTERNAL_SERVER_ERROR
        return err
    end
    ngx.status = HTTP_UNAUTHORIZED
end

function _M:authenticate()
    local authz_header = ngx.var.http_authorization
    if not authz_header then
        local err = _challenge(self)
        if err then
            return nil, err
        end
        return nil, 'missing authorization header'
    end

    local auth, err = parse_authz_header(authz_header)
    if err then
        log(ngx.WARN, 'parse_authz_header: ' .. err)
        ngx.status = HTTP_FORBIDDEN
        return nil, 'parse_authz_header: ' .. err
    end
    for _, field in pairs({'response', 'username', 'realm', 'uri', 'qop', 'nonce', 'cnonce', 'nc'}) do
        if not auth[field] then
            return nil, 'missing field in authorization header: ' .. field
        end
    end
    local code, reason = self:verify(auth)
    if code == HTTP_UNAUTHORIZED then
        -- stale nonce or authentication timed-out
        err = _challenge(self, true)
        if err then
            return nil, err
        end
        return nil, 'expired nonce'
    end
    ngx.status = code
    return auth, reason
end

return _M
