-- Copyright (C) Peter Zhu (starsz), UPYUN Inc.


local bit = require "bit"
local ngx_re = require "ngx.re"
local cjson = require "cjson.safe"

local band   = bit.band
local lshift = bit.lshift
local rshift = bit.rshift

local str_byte = string.byte

local _M = { _VERSION = "0.0.1" }

local mt = { __index = _M }

local IPV4                 = 1
local IPV6                 = 2

local INVALID_FILE_PATH    = "invalid file path"
local INVALID_DB_FORMAT    = "invalid db format"
local IP_FORMAT_ERR        = "invalid ip format"
local LANGUAGE_ERR         = "language not support"
local DATABASE_ERR         = "database error"

local gsub         = string.gsub
local insert       = table.insert
local concat       = table.concat
local ngx_re_match = ngx.re.match
local ipv4_pattern = [[(((\d{1,2})|(1\d{2})|(2[0-4]\d)|(25[0-5]))\.){3}((\d{1,2})|(1\d{2})|(2[0-4]\d)|(25[0-5]))]]

-- TODO: Use graceful function
local function split(content, ch)
    local res = {}
    local start = 1
    for i=1, #content, 1 do
        if content:sub(i,i) == ch then
            stop = i

            if start == stop then
                insert(res, "")
            else
                insert(res, content:sub(start, stop-1))
            end
            start = stop + 1
        end
    end
    insert(res, content:sub(start, #content))

    return res
end


local function _uint16(a, b)
    if not a or not b then
        return nil
    end

    local u = lshift(a, 8) + b
    if u < 0 then
        u = u + math.pow(2, 16)
    end

    return u
end


local function _uint32(a, b, c, d)
    if not a or not b or not c or not d then
        return nil
    end

    local u = lshift(a, 24) + lshift(b, 16) + lshift(c, 8) + d
    if u < 0 then
        u = u + math.pow(2, 32)
    end

    return u
end


local function read_node(data, node, index)
    local off = node * 8 + index * 4 + 1
    return _uint32(str_byte(data, off, off+3))
end


local function check_addr_type(addr)
    local m, err = ngx_re_match(addr, ipv4_pattern)
    if m then
        return IPV4
    end

    -- TODO: support IPV6
    return IPV6
end


local function search(self, ip, bitcount)
    local node
    if bitcount == 32 then
        node = self.v4offset
    else
        node = 0
    end

    for i = 0, bitcount-1, 1 do
        if node > self.meta.node_count then
            break
        end

        local temp = ip[rshift(i, 3)+1]
        node = read_node(self.data, node, band(rshift(band(0xFF, temp), (7 - i % 8)), 1))
    end

    if node > self.meta.node_count then
        return node, nil
    end

    return -1,  INVALID_DB_FORMAT
end


local function getdata(filepath)
    if not filepath then
        return nil, INVALID_FILE_PATH
    end

    local file, err = io.open(filepath, "rb")
    if not file then
        return nil, err
    end

    local data, err = file:read("*all")
    if not data then
        file:close()
        return nil, err
    end

    file:close()
    return data
end


local function parse_data(data)
    local db = {}
    local meta_length = _uint32(str_byte(data, 1, 4))
    if not meta_length then
        return nil, INVALID_DB_FORMAT
    end
    -- meta:
    --      build
    --      ip_version
    --      languages
    --      node_count
    --      total_size
    --      fields

    local meta, err = cjson.decode(data:sub(5, 5+meta_length))
    if not meta then
        return nil, err
    end

    local i = 0
    local v4offset = 0
    local content_data = data:sub(5+meta_length)
    for i=0, 95, 1 do
        if v4offset >= meta.node_count then
            break
        end

        if i >= 80 then
            v4offset = read_node(content_data, v4offset, 1)
        else
            v4offset = read_node(content_data, v4offset, 0)
        end
    end

    return {meta = meta, data = content_data, v4offset = v4offset}
end


local function resolve(db, node)
    local resolved = node + db.meta.node_count * 7
    if resolved >= db.meta.total_size then
        return nil, DATABASE_ERR
    end

    local size = _uint16(str_byte(db.data, resolved+1, resolved+2))
    if resolved + 2 + size > (#db.data) then
        return nil, DATABASE_ERR
    end

    local res = db.data:sub(resolved+2+1, resolved+2+size)

    return res, nil
end


function _M.new(filepath)
    local data, err = getdata(filepath)
    if not data then
        return nil, err
    end

    local db = parse_data(data)
    if not db then
        return nil, INVALID_DB_FORMAT
    end

    return setmetatable(db, mt)
end


local function find0(self, addr)
    local ip_type = check_addr_type(addr)

    local node, err
    if ip_type == IPV4 then
        local ip, err  = ngx_re.split(addr, "\\.")
        if not ip then
            return nil, err
        end
        node, err = search(self, ip, 32)
    elseif ip_type == IPV6 then
        node, err = search(self, addr, 128)
    end

    if not node then
        return nil, err
    end

    local content, err = resolve(self, node)
    if not content then
        return nil, err
    end

    local body, err = split(content, "\t")
    if not body then
        return nil, err
    end

    return body
end


function _M.find(self, addr, language)
    if language == nil then
        language = "CN"
    end

    if self.meta and not self.meta.languages[language] then
        return nil, LANGUAGE_ERR
    end

    local body, err = find0(self, addr)
    if not body then
        return nil, errr
    end

    local off = self.meta.languages[language]
    if off + #(self.meta.fields) > #body then
        return nil, INVALID_DB_FORMAT
    end

    return concat(body, " ", off+1, off+#(self.meta.fields)), nil
end


function _M.find_tab(self, addr, language)
    if language == nil then
        language = "CN"
    end

    if self.meta and not self.meta.languages[language] then
        return nil, LANGUAGE_ERR
    end

    local off = self.meta.languages[language]
    if off + #(self.meta.fields) > #body then
        return nil, INVALID_DB_FORMAT
    end

    local res = {}
    for k, v in ipairs(self.meta.fields) do
        res[v] = body[k]
    end

    return res, nil
end


function _M.find_json(self, addr, language)
    if language == nil then
        language = "CN"
    end

    if self.meta and not self.meta.languages[language] then
        return nil, LANGUAGE_ERR
    end

    local body, err = find0(self, addr)
    if not body then
        return nil, err
    end

    local off = self.meta.languages[language]
    if off + #(self.meta.fields) > #body then
        return nil, INVALID_DB_FORMAT
    end

    local res = {}
    for k, v in ipairs(self.meta.fields) do
        res[v] = body[k]
    end

    return cjson.encode(res), nil
end


return _M
