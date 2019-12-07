Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Description](#description)
* [Synopsis](#synopsis)
* [Methods](#methods)
* [Installation](#installation)
* [Limitations](#limitations)
* [Author](#author)
* [License](#license)

Name
====

lua-resty-http-digest

Status
======

beta

Description
===========

lua-resty-http-digest library implements "HTTP Digest Access Authentication"(specified by [RFC7616](https://tools.ietf.org/html/rfc7616)) in Lua for OpenResty.

Synopsis
========

```nginx
lua_package_path "/path/to/lua-resty-http-digest/lib/?.lua;;";

location = /protected {
    access_by_lua_block {
        local function get_password(name)
            return 'root'
        end

        local http_digest = require 'resty.http_digest'
        local t, err = http_digest:new({
            get_password = function(name) return 'root' end,
            realm = 'example.com',
            nonce_age = 60,
            auth_timeout = 60,
            max_replays = 20,
            algorithm = http_digest.MD5,
            redis = {
                db = '0',
                host = '127.0.0.1',
                port = 6379,
                timeout = 1000,
                keepalive_idle_timeout = 20000,
                keepalive_pool_size = 5,
            },
        })
        if err then
            ngx.status = 500
            ngx.log(ngx.ERR, err)
            ngx.exit(500)
        end
        local auth, err = t:authenticate()
        if ngx.status == ngx.HTTP_UNAUTHORIZED then
            -- send challenge
            ngx.exit(ngx.status)
        end

        if err then
            ngx.log(ngx.ERR, err)
            ngx.exit(ngx.status)
        end

        ngx.say('Welcome ' .. auth.username)
    }
}
```

[Back to TOC](#table-of-contents)

Methods
=======

new
---
`syntax: t, err = class:new(opts)`

Creates an authenticator object. Returns `nil` and a message string on error.

It accepts a `opts` table argument. The following options are supported:

* `get_password`: a function that returns `(password, error)` for the given username.

Required.

The signature of this function is: `(username: string) -> (password: string, error)`

* `realm`

Optional. Default: `ngx.var.http_host`

* `nonce_age`

Optional. Default: `60`

* `auth_timeout`

Optional. Default: `60`

* `max_replays`

Optional. Default: `20`

* `algorithm`

Optional. Default: `http_digest.MD5`. Available: `http_digest.MD5`, `http_digest.SHA256`

* `redis.db`

Optional. Default: `0`

* `redis.host`

Optional. Default: `127.0.0.1`

* `redis.port`

Optional. Default: `6379`

* `redis.timeout`

Optional. Default: `1000`(1 sec)

* `redis.keepalive_idle_timeout`

Optional. Default: `nil`

* `redis.keepalive_pool_size`

Optional. Default: `nil`

[Back to TOC](#table-of-contents)

authenticate
------------
`syntax: info, err = t:authenticate()`

Validates the `Authorization` header and returns information extracted from `Authorization` header. In case of errors, it will set corresponding status code and returns an error message.

[Back to TOC](#table-of-contents)

Installation
============

[Back to TOC](#table-of-contents)

Limitations
===========

* `realm` cannot contain space char or quote
* only support `MD5` and `SHA256` algorithms, `*-sess` algorithms are not implemented
* only `auth` qop is supported

[Back to TOC](#table-of-contents)

Author
======

GitHub @knight42

[Back to TOC](#table-of-contents)

License
======

lua-resty-http-digest is licensed under the [MIT](./LICENSE) license.

[Back to TOC](#table-of-contents)
