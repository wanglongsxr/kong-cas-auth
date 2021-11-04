local http = require('resty.http')
local cjson = require('cjson')
local xml2lua = require('lua.xml2lua.xml2lua')
local handler = require("lua.xml2lua.tree")
local ck = require('resty.cookie')

local kong = kong
local kong_port = ":8000"

-- ngx请求url
local function _uri_without_ticket()
   return ngx.var.scheme .. "://" .. ngx.var.host ..  ngx.re.sub(ngx.var.request_uri, "[?&]ticket=.*", "")
end

--从硬盘中读取文件
local function open_diff(path)
   --”r“代表只读
   local f,errInfo = io.open(path, "r")
   if errInfo then
      return "",errInfo
   end
   --"a" 从当前位置开始剩余的所有字符串，如果在文件末尾，则返回空串""
   local json = f:read("*a");
   f:close()
   return json
end
--从硬盘中写入文件
local function write_diff(path,content)
   --”w“打开的文件不存在则创建，w会覆盖原有的内容
   local f,errInfo = io.open(path, "w")
   if errInfo then
      return errInfo
   end
   local json = f:write(content);
   f:flush()
   f:close()
end

local function get(url, headers, query)
   local httpc = http.new()
   local res, error = httpc:request_uri(url, {
      ssl_verify = ssl_verify or false,
      method = "GET",
      headers = headers,
      query = query,
   })
   httpc:close()

   return res, error
end

local function post(url, headers, query, body)
   local httpc = http.new()
   local response, error = httpc:request_uri(url, {
      ssl_verify = ssl_verify or false,
      method = "POST",
      headers = headers,
      query = query,
      body = body,
   })
   httpc:close()

   return response, error
end

-- 获取登陆票据TGT(Ticket Grangting Ticket)
local function getTGT(args,conf)
   local url = conf.tenant.cas_url .. "/v1/tickets"
   local headers = {
      ["Content-type"] = "application/x-www-form-urlencoded"
   }
   local query = {
      service = _uri_without_ticket()
   }
   local body = "username=" ..args.username .."&password="..args.pwd
   return post(url, headers, query, body)
end

-- 获取ST票据
local function getST(ticket,conf)
   local url = conf.tenant.cas_url .. "/v1/tickets/"..ticket
   local headers = {
      ["Content-type"] = "application/x-www-form-urlencoded"
   }
   local body = "service=" .. _uri_without_ticket()

   return post(url, headers, query, body)
end

-- 校验ST(Service Ticket)
local function validateST(ticket,conf)
   local url = conf.tenant.cas_url .. "/serviceValidate"
   local query = {
      service = _uri_without_ticket(),
      ticket = ticket
   }
   return get(url, nil, query)
end

--设置cookie
local function _set_cookie(val,max_age,conf)
   local cookie = ck:new()
   cookie:set({
      key=conf.tenant.cookie_name,
      value=val,
      max_age=max_age,
      path=ngx.var.uri
   })
   --设置自定义参数
   cookie:set({
      key = conf.tenant.name,
      value = conf.tenant.groupName,
      max_age=max_age,
      path=ngx.var.uri
   })
end
--获取cookie
local function _get_cookie(conf)
   return ngx.var["cookie_" .. conf.tenant.cookie_name]
end

--持久化硬盘以及客户端设置cookie
local function _set_store_and_cookie(_cookie, conf)
   local content = {}
   --组装内容
   content["expired_time"] = os.time() + conf.tenant.session_lifetime
   content["tgt"] = _cookie
   local json = cjson.encode(content)
   local md5_data = ngx.md5(json .. "&" .. conf.tenant.secret)
   --写入磁盘
   local errinfo = write_diff(conf.tenant.tgt.. md5_data .. ".cookie", json)
   if errinfo then
      kong.log.inspect("持久化失败··················",errinfo)
      return false
   end
   --cookie过期时间 2^31 - 1 = 2147483647 = 2038-01-19 04:14:07
   local permanent_time = 2147483647
   --同步客户端cookie
   _set_cookie(md5_data, permanent_time, conf)
   return true
end

--删除cookie
local function destroy_cookie(conf)
   local store = ngx.shared[conf.store_name]
   store:delete(_get_cookie(conf))
   _set_cookie("deleted",0,conf)
end


local function _validate(args,conf)
   --获取登录票据
   local TGTres, TGTerror = getTGT(args,conf)
   if TGTres.status ~= 201 then
      ngx.log(ngx.ERR,"failed to request: ", TGTerror)
      return
   end
   -- 登陆票据
   local login_ticket = string.match(string.match(TGTres.body, "action=\"([^%s]+)\""), "TGT-.+")
   if not login_ticket then
      ngx.log(ngx.ERR,"failed to request TGT: ")
   end
   ---- 2.获取ST(Service Ticket)
   local STres, STerror = getST(login_ticket,conf)
   -- 校验参数
   if STres.status ~= 200 then
      ngx.log(ngx.ERR,"failed to request ST", STerror)
   end

   -- 3. 校验ST(Service Ticket)
   local res, error = validateST(STres.body,conf)
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
            kong.log.inspect("cas的返回结果为：",jsonData)
            --字段筛选
            local json = {}
            local filter_ele = conf.tenant.userinfo
            for k,v in ipairs(filter_ele) do
               json[v] = handler.root.serviceResponse.authenticationSuccess.userInfo[v]
            end
            return json,login_ticket
         end
      else
         ngx.log(ngx.INFO, "CAS serviceValidate failed: " .. res.body)
      end
   else
      ngx.log(ngx.ERR, err)
   end
   return nil
end

--首次登录
local function first_access(conf)
   local server_service = conf.tenant.theme
   local cas_login = conf.tenant.login_host .. "/login?system="..server_service.."&" .. ngx.encode_args({ service = _uri_without_ticket() })
   ngx.redirect(cas_login, ngx.HTTP_MOVED_TEMPORARILY)
end

--cookie登录
local function with_cookie(_cookie,conf)
   local diff_path = conf.tenant.tgt.._cookie..".cookie"
   --从硬盘中取tgt
   local json,errInfo = open_diff(diff_path)
   if errInfo then
      kong.log.err("tgt is not exist or cookie is illegal!")
      --删除cookie，并跳转到登录页
      _set_cookie("deleted",0,conf)
      first_access(conf)
   end

   local tatObject = cjson.decode(json)
   local tgt = tatObject.tgt
   --判断cookie是否过期
   local expired = tatObject.expired_time

   --如果cookie时间过期,浏览器将不携带cookie
   if expired < os.time() then
      kong.log.inspect("cookie is expired")
      --判断tgt有没有过期，如果没有过期，重新设置cookie时长
      local STres, STerror =getST(tgt,conf)
      if STres.status ~= 200 then
         kong.log.inspect("tgt is expired")
         --删除之前cookie的文件
         os.remove(diff_path)
         --删除cookie，并跳转到登录页
         _set_cookie("deleted",0,conf)
         first_access(conf)
      end
   end
   --删除之前cookie的文件
   os.remove(diff_path)
   --刷新cookie，则重新设置cookie
   _set_store_and_cookie(tgt,conf)
   kong.log.inspect(">>>>>>>>>进入了最后一步，cookie阶段>>>>>>>>>")
end

--cas校验登录
local function validate_with_CAS(args,conf)
   --cas登录
   local user,tgt = _validate(args,conf)
   kong.log.err("筛选后的字段结果为：",cjson.encode(user))
   --校验成功之后 set cookie
   if user and _set_store_and_cookie(tgt,conf) then
      -- 同时成功后则转发到目标地址
      ngx.redirect(_uri_without_ticket(), ngx.HTTP_MOVED_TEMPORARILY)
   else
      --失败跳回登录页
      first_access(conf)
   end
end

return {
   first_access = first_access;
   validate_with_CAS = validate_with_CAS;
   with_cookie = with_cookie;
   open_diff = open_diff;

   destroy_sessionId = destroy_cookie;
}
