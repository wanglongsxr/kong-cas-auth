local BasePlugin = require "kong.plugins.base_plugin"
local cas_handlers = require "kong.plugins.cas-auth.cas_helpers"
local redisUtil = require "resty.redisUtil"
local redisHost = "xxxxxx"
local redisPort = "xxxxxx"
local redisPwd = "xxxxxx"

local kong = kong
local CasAuthHandler = BasePlugin:extend()
local red = redisUtil.new({ host = redisHost, password = redisPwd, port = redisPort })

function CasAuthHandler:new()
    CasAuthHandler.super.new(self, "cas-auth")
end

function CasAuthHandler:access(conf)
    CasAuthHandler.super.access(self)
    --接口防刷（限制：1秒请求超过100次，则被限制10分钟，10分钟后才可以访问）
    local clientIP = ngx.req.get_headers()["X-Real-IP"]
    if clientIP == nil then
        clientIP = ngx.req.get_headers()["x_forwarded_for"]
    end
    if clientIP == nil then
        clientIP = ngx.var.remote_addr
    end
    local incrKey = "user:" .. clientIP .. ":freq"
    local blockKey = "user:" .. clientIP .. ":block"

    red:exec(
            function(red)
                local is_block, err = red:get(blockKey)
                --判断是否被锁住
                if tonumber(is_block) == 1 then
                    ngx.exit(ngx.HTTP_FORBIDDEN)
                    return
                end
                --没锁柱
                local times = red:incr(incrKey)
                if times == 1 then
                    red:expire(incrKey, 1)
                end
                --1秒请求超过100次则锁住，10分钟不能登录
                if times > 100 then
                    red:setnx(blockKey, 1)
                    red:expire(blockKey, 600)
                end
            end
    )

    --cas验证登录
    local cookie = ngx.var["cookie_" .. conf.cookie_name]
    local ticket = ngx.var.arg_ticket

    if cookie ~= nil then
        kong.log.inspect("cookie不为空------------", cookie)
        return cas_handlers.with_sessionId(cookie, conf)
    elseif ticket ~= nil then
        kong.log.inspect("ticket不为空------------", ticket)
        return cas_handlers.validate_with_CAS(ticket, conf)
    else
        kong.log.inspect("第一次访问--------------")
        return cas_handlers.first_access(conf)
    end
end

return CasAuthHandler