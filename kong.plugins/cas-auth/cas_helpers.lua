local http = require('resty.http')
local cjson = require('cjson')
local xml2lua = require('lua.xml2lua.xml2lua')
local handler = require("lua.xml2lua.tree")

local kong = kong
local kong_port = ":8000"

local function _to_table(v)
   if v == nil then
      return {}
   elseif type(v) == "table" then
      return v
   else
      return { v }
   end
end

-- ngx请求url
local function _uri_without_ticket()
   return ngx.var.scheme .. "://" .. ngx.var.host .. kong_port ..  ngx.re.sub(ngx.var.request_uri, "[?&]ticket=.*", "")
end

--首次登录
local function first_access(conf)
   kong.log.inspect("转发后的地址：",_uri_without_ticket())
   local cas_login = conf.cas_url .. "/login?" .. ngx.encode_args({ service = _uri_without_ticket() })
   ngx.redirect(cas_login, ngx.HTTP_MOVED_TEMPORARILY)
end

local function _set_cookie(cookie_str)
   local h = _to_table(ngx.header['Set-Cookie'])
   table.insert(h, cookie_str)
   ngx.header['Set-Cookie'] = h
end

local function _get_sessionId(conf)
   return ngx.var["cookie_" .. conf.cookie_name]
end

local function _set_our_cookie(val,conf)
   _set_cookie(conf.cookie_name .. "=" .. val .. conf.cookie_params)
end

--cookie登录
local function with_sessionId(sessionId,conf)
   -- 从内存中拿出cookie
   local store = ngx.shared[conf.store_name]
   local user = store:get(sessionId);
   if user == nil then
      --cookie过期
      --删除cookie，并跳转到登录页，如果不删除，则会进入死循环（cas校验那里）
      _set_our_cookie("deleted; Max-Age=0",conf)
      first_access(conf)
   else
      -- 刷新过期时间
      store:set(sessionId, user, conf.session_lifetime)

      -- 导出数据
      ngx.req.set_header("REMOTE_USER", user)
      ngx.req.set_header("REMOTE_USER", user)
      ngx.req.set_header("X-Forwarded-Login", user)
      ngx.req.set_header("X-Forwarded-Name", user)

      kong.log.inspect(">>>>>>>>>进入了最后一步，cookie阶段>>>>>>>>>")
   end
end

--给cookie里面塞值
local function _set_store_and_cookie(sessionId, user,conf)
   --获取共享内存的值
   local store = ngx.shared[conf.store_name]
   --add方法与set方法区别在于 不会插入重复的键，如果待插入的key已经存在，将会返回false、nil和和err="exists"
   local success, err, forcible = store:add(sessionId, user, conf.session_lifetime)
   if success then
      --成功插入
      if forcible then
         --true表明需要通过强制删除（LRU算法）共享内存上其他字典项来实现插入，false表明没有删除共享内存上的字典项来实现插入
         ngx.log(ngx.WARN, "CAS cookie store is out of memory")
      end
      _set_our_cookie(sessionId,conf)
   else
      --插入失败
      if err == "no memory" then
         --操作失败
         ngx.log(ngx.EMERG, "CAS cookie store is out of memory")
      elseif err == "exists" then
         --说明key已存在
         ngx.log(ngx.ERR, "Same CAS ticket validated twice, this should never happen!")
      end
   end
   return success
end

--cas校验接口
local function _validate(ticket,conf)
   local httpc = http.new()
   local service_url = _uri_without_ticket()
   local res, err = httpc:request_uri(conf.cas_url .. "/serviceValidate", { query = { ticket = ticket, service = service_url }, keepalive = false  })

   --判断是否校验成功
   if res and res.status == ngx.HTTP_OK and res.body ~= nil then
      if string.find(res.body, "<cas:authenticationSuccess>") then
         local m = ngx.re.match(res.body, "<cas:user>(.*?)</cas:user>");
         if m then
            local str = res.body;
            str = string.gsub(str,"cas:","")
            --如果之前已有值，则重置
            if(next(handler.root) ~= nil) then
               handler = handler:new()
            end
            --解析xml数据为lua table
            local parser = xml2lua.parser(handler)
            parser:parse(str)
            local jsonData = cjson.encode(handler.root);
            kong.log.err("最后的返回结果为：",jsonData)
            return m[1]
         end
      else
         ngx.log(ngx.INFO, "CAS serviceValidate failed: " .. res.body)
      end
   else
      ngx.log(ngx.ERR, err)
   end
   return nil
end

--cas登录后校验，成功则转发
local function validate_with_CAS(ticket,conf)
   --cas校验
   local user = _validate(ticket,conf)
   --校验成功后set cookie
   if user and _set_store_and_cookie(ticket, user,conf) then
      -- 同时成功后则转发到目标地址
      ngx.redirect(_uri_without_ticket(), ngx.HTTP_MOVED_TEMPORARILY)
   else
      --失败跳回登录页
      first_access(conf)
   end
end

--删除cookie
local function destroy_sessionId(conf)
   local store = ngx.shared[conf.store_name]
   store:delete(_get_sessionId(conf))
   _set_our_cookie("deleted; Max-Age=0",conf)
end

local function getUsername(conf)
   local sessionId = _get_sessionId(conf)
   local store = ngx.shared[conf.store_name]
   if sessionId ~= nil then
      return store:get(sessionId)
   else
      return 'test'
   end
end

return {
   first_access = first_access;
   validate_with_CAS = validate_with_CAS;
   with_sessionId = with_sessionId;

   destroy_sessionId = destroy_sessionId;
}
