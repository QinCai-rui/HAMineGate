-- THIS IS NOT A STANDALONE LUA FILE, BUT MEANT TO BE USED AS A MODULE.

--[[
  This file is part of HAMineGate.
  Copyright (C) 2026 Raymont Qin

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at https://mozilla.org/MPL/2.0/.
]]

---@diagnostic disable: undefined-global

do
    local src = debug.getinfo(1, "S").source
    if src:match("^@") then
        src = src:sub(2)
    end
    local dir = src:match("^(.*[\\/])")
    if dir then
        package.path = dir .. "?.lua;" .. package.path
    end
end

local string_len  = string.len
local string_format = string.format

local util = require("minecraft_prot_util")
local parser = require("minecraft_prot_parser")
local policy = require("minecraft_prot_policy")

-- HAProxy action
local function mc_handshake(txn)
    local raw = txn.req:dup()
    util.log_debug(string_format("mc_handshake: txn.req.len=%d", string_len(raw or "")))

    -- Fail closed until we have a complete, validated handshake.
    txn:set_var('txn.mc_proto', 0)
    txn:set_var('txn.mc_host', '')
    txn:set_var('txn.mc_state', 0)
    txn:set_var('txn.mc_blocked', 1)
    txn:set_var('txn.mc_hostname_allowed', 0)

    local res, proto, host, state = parser.read_mc_handshake({ raw, 1 })
    util.log_debug(string_format("mc_handshake: result=%s proto=%s host=%s state=%s",
        tostring(res), tostring(proto), tostring(host), tostring(state)))

    if res == nil then
        -- do nothing, HAProxy may call us again when more data arrives
        return
    elseif res == false then
        txn:set_var('txn.mc_proto', 0)
        txn:set_var('txn.mc_host', '')
        txn:set_var('txn.mc_state', 0)
    else
        txn:set_var('txn.mc_proto', proto)
        txn:set_var('txn.mc_host', host)
        txn:set_var('txn.mc_state', state)

        local src_ip = txn.sf:src()
        local blocked = policy.is_blocked_ip(src_ip) and 1 or 0
        local allowed = policy.hostname_is_allowed(host) and 1 or 0

        txn:set_var('txn.mc_blocked', blocked)
        txn:set_var('txn.mc_hostname_allowed', allowed)
    end
end

core.register_action('mc_handshake', { 'tcp-req' }, mc_handshake, 0)
