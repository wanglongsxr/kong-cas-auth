local BasePlugin = require "kong.plugins.base_plugin"
local cas_helpers = require "kong.plugins.cas-proxy.helpers"
local cjson = require "cjson"
local redisUtil = require "resty.redisUtil"
local redisHost = "xxx"
local redisPort = "6379"
local redisPwd = "xxx"
local lfs = require "lfs"

local kong = kong
local CasProxyHandler = BasePlugin:extend()
local red = redisUtil.new({ host = redisHost, password = redisPwd, port = redisPort })
local path = "/opt/share/json/"

function CasProxyHandler:new()
    CasProxyHandler.super.new(self, "cas-proxy")
end

--请求地址
local function request_uri()
    return kong.request.get_scheme() .. "://" .. kong.request.get_host() .. kong.request.get_path_with_query()
end

--文件读取并转换为table
local function FileRead(path)
    local allContent = {}
    for file in lfs.dir(path) do
        --排除linux系统的.xxx文件
        if file ~= "." and file ~= ".." then
            local json, errInfo = cas_helpers.open_diff(path .. file)
            if errInfo then
                allContent = {}
                break ;
            end
            table.insert(allContent, cjson.decode(json))
        end
    end
    return allContent
end

--接口防刷
local function anti_brush()
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
end

--租户处理
local function multi_tenancy()
    local allContent = FileRead(path)
    if not allContent or allContent == ngx.null then
        return
    end
    local tenant
    local pass_url
    --根据id排序
    table.sort(allContent, function(a, b)
        return (tonumber(a.id) < tonumber(b.id))
    end)
    --筛选租户
    for key, value in ipairs(allContent) do
        tenant = string.match(request_uri(), value.serviceId)
        if tenant then
            tenant = value
            break ;
        end
    end
    --放行资源
    if tenant then
        for key, value in ipairs(tenant.filter) do
            pass_url = string.match(request_uri(), ".*" .. value .. ".*")
            if pass_url then
                break ;
            end
        end
    end
    return tenant, pass_url
end

function CasProxyHandler:access(conf)
    CasProxyHandler.super.access(self)
    --租户详情
    local tenant_info, pass_url = multi_tenancy()
    if not tenant_info then
        return ngx.say("user is not exist!!")
    end
    kong.log.inspect("租户信息为：", tenant_info)
    --放行资源
    if pass_url then
        return
    end
    conf["tenant"] = tenant_info
    --接口防刷（限制：1秒请求超过100次，则被限制10分钟，10分钟后才可以访问）
    anti_brush()

    --cas验证登录
    local cookie = ngx.var["cookie_" .. conf.cookie_name]
    local body, err, mimetype = kong.request.get_body()

    if cookie ~= nil then
        kong.log.inspect("cookie不为空------------", cookie)
        return cas_helpers.with_cookie(cookie, conf)
    elseif body ~= nil then
        kong.log.inspect("body体不为空------------", body)
        return cas_helpers.validate_with_CAS(body, conf)
    else
        kong.log.inspect("第一次访问--------------")
        return cas_helpers.first_access(conf)
    end
end

return CasProxyHandler