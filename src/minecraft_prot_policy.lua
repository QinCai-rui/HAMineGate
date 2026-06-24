-- THIS IS NOT A STANDALONE LUA FILE, BUT MEANT TO BE USED AS A MODULE.

--[[
  This file is part of HAMineGate.
  Copyright (C) 2026 Raymont Qin

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at https://mozilla.org/MPL/2.0/.
]]

---@diagnostic disable: undefined-global

local string_len  = string.len
local string_sub  = string.sub
local string_lower = string.lower

local util = require("minecraft_prot_util")

local BLOCKED_IPS_PATH = "/root/haproxy/blocked_ips.txt"
local ALLOWED_HOSTNAMES_PATH = "/root/haproxy/allowed_hostnames.txt"

local blocked_ips = util.list_to_set(util.load_lines(BLOCKED_IPS_PATH), string_lower)
local allowed_host_patterns = util.load_lines(ALLOWED_HOSTNAMES_PATH)

local M = {}

function M.is_blocked_ip(src_ip)
    if not src_ip or src_ip == "" then
        return false
    end

    return blocked_ips[string_lower(src_ip)] == true
end

function M.hostname_is_allowed(hostname)
    if not hostname or hostname == "" then
        return false
    end

    hostname = string_lower(hostname)
    -- normalise: remove a trailing dot (for some reason present in handshake hostname in state 2, ie player logging in)
    hostname = hostname:gsub("%.$", "")
    for _, pattern in ipairs(allowed_host_patterns) do
        pattern = string_lower(util.trim(pattern))
        if pattern ~= "" then
            local wildcard_suffix = pattern:match("^%*%.(.+)$")
            if wildcard_suffix ~= nil then
                if string_len(hostname) > string_len(wildcard_suffix) then
                    local suffix = string_sub(hostname, -string_len(wildcard_suffix))
                    if suffix == wildcard_suffix and string_sub(hostname, -(string_len(wildcard_suffix) + 1), -(string_len(wildcard_suffix) + 1)) == "." then
                        return true
                    end
                end
            end

            if hostname == pattern then
                return true
            end

            if string_len(hostname) > string_len(pattern) then
                local suffix = string_sub(hostname, -string_len(pattern) - 1)
                if suffix == "." .. pattern then
                    return true
                end
            end
        end
    end

    return false
end

return M
