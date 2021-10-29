local BasePlugin = require "kong.plugins.base_plugin"
local handlers = require "kong.plugins.cas-auth.cas_helpers"

local CasLogoutHandler = BasePlugin:extend()

function CasLogoutHandler:new()
    CasLogoutHandler.super.new(self, "cas-logout")
end

function CasLogoutHandler:access(conf)
    CasLogoutHandler.super.access(self)

    local cas_uri = conf.cas_url;
    -- 清除session
    handlers.destroy_sessionId(conf);
    -- redirect to cas logout
    return ngx.redirect(cas_uri .. "/logout")
end

return CasLogoutHandler

