package.path = 'D:/develop/idea/yingxiong/kong-config-ads/lua'
package.path = package.path .. '/?.lua';

local xml2lua = require("xml2lua.xml2lua")
--Uses a handler that converts the XML to a Lua table
local handler = require("xml2lua.tree")

local xml = [[
<serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
    <authenticationSuccess>
        <user>long.wang</user>
        <italentUserId>152119372</italentUserId>
        <userInfo>
            <username>long.wang</username>
            <realname>王龙</realname>
            <phone>15712890761</phone>
            <email>long.wang@yingxiong.com</email>
            <locked>0</locked>
            <id>1825</id>
            <bdcId>1726</bdcId>
            <sex>0</sex>
            <createDate>2021-04-01 11:30:50</createDate>
            <clientName>chengdu-client</clientName>
        </userInfo>
        <ldap>
            <cn>王龙</cn>
            <displayName>王龙</displayName>
            <sn>王</sn>
            <givenName>龙</givenName>
            <dn>CN=王龙,OU=大数据中心,OU=SP支撑平台,OU=英雄互娱,DC=yxhy,DC=com</dn>
            <memberOf>CN=jira,OU=英雄互娱,DC=yxhy,DC=com</memberOf>
            <objectGUID>S60/v2x7skmAQGwmwa3/bA==</objectGUID>
            <sAMAccountName>long.wang</sAMAccountName>
        </ldap>
    </authenticationSuccess>
</serviceResponse>
]]
--Instantiates the XML parser
local parser = xml2lua.parser(handler)
parser:parse(xml)

--Manually prints the table (since the XML structure for this example is previously known)
for i, p in pairs(handler.root.serviceResponse.authenticationSuccess.userInfo) do
    print(i, p)
end