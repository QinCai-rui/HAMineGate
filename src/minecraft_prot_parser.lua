-- THIS IS NOT A STANDALONE LUA FILE, BUT MEANT TO BE USED AS A MODULE.

--[[
  This file is part of HAMineGate.
  Copyright (C) 2026 Raymont Qin

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at https://mozilla.org/MPL/2.0/.
]]

-- This file is based on the following work (which was made for a different purpose)
-- https://gist.github.com/nathan818fr/a078e92604784ad56e84843ebf99e2e5
-- ORIGINAL LICENSE below:
--[[
  MIT LICENSE
  Copyright 2021 Nathan Poirier
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
]]

---@diagnostic disable: undefined-global

local string_len  = string.len
local string_byte = string.byte
local string_sub  = string.sub
local string_format = string.format

local util = require("minecraft_prot_util")

local M = {}

-- Returns the number of readable bytes in this payload.
function M.payload_readable_len(payload)
    return string_len(payload[1]) - payload[2] + 1
end

-- Gets a VarInt at the current reader_index and increases the reader_index by its length.
function M.payload_read_varint(payload, max_bytes, nilable)
    local ret   = 0
    local bytes = 0
    local b
    while true do
        b = string_byte(payload[1], payload[2] + bytes)
        if b == nil then
            if nilable then
                return
            else
                return -1
            end
        end

        ret   = ret | ((b & 127) << (bytes * 7))
        bytes = bytes + 1

        if b < 128 then
            payload[2] = payload[2] + bytes
            return ret
        end

        if bytes >= max_bytes then
            payload[2] = payload[2] + bytes
            return -1
        end
    end
end

-- Gets a String at the current reader_index and increases the reader_index by its length.
function M.payload_read_string(payload, max_prefix_bytes, max_utf8_len)
    local str_len = M.payload_read_varint(payload, max_prefix_bytes, false)
    if (str_len == -1 or str_len == 0 or str_len > max_utf8_len or str_len > M.payload_readable_len(payload)) then
        return false
    end
    local str = string_sub(payload[1], payload[2], payload[2] + str_len - 1)
    payload[2] = payload[2] + str_len
    return str
end

-- Decode the minecraft handshake packet.
function M.read_mc_handshake(payload)
    if payload[1] == nil then
        util.log_debug("mc_handshake: no payload yet")
        return
    end

    util.log_debug(string_format(
        "mc_handshake: raw_len=%d readable=%d hex=%s",
        string_len(payload[1]),
        M.payload_readable_len(payload),
        util.hexdump(payload[1])
    ))

    -- read packet len
    local packet_len = M.payload_read_varint(payload, 3, true)
    util.log_debug("mc_handshake: packet_len=" .. tostring(packet_len))
    if packet_len == nil then
        util.log_debug("mc_handshake: need more data for packet_len")
        return
    end
    if packet_len == -1 or packet_len > 4096 then
        util.log_debug("mc_handshake: invalid packet_len, fast-fail")
        return false
    end
    if packet_len > M.payload_readable_len(payload) then
        util.log_debug("mc_handshake: incomplete packet, waiting more data")
        return
    end

    -- read packet id (for handshakes this must be 0)
    local packet_id = M.payload_read_varint(payload, 3, false)
    util.log_debug("mc_handshake: packet_id=" .. tostring(packet_id))
    if packet_id == -1 or packet_id ~= 0 then
        util.log_debug("mc_handshake: invalid packet_id")
        return false
    end

    -- read protocol version
    local protocol_version = M.payload_read_varint(payload, 5, false)
    util.log_debug("mc_handshake: protocol_version=" .. tostring(protocol_version))
    if protocol_version == nil or protocol_version == -1 or protocol_version <= 0 then
        util.log_debug("mc_handshake: illegal protocol_version, fast-fail")
        return false
    end

    -- read hostname
    local hostname = M.payload_read_string(payload, 3, 255)
    util.log_debug("mc_handshake: hostname_raw=" .. tostring(hostname))
    if hostname == false then
        util.log_debug("mc_handshake: illegal hostname, fast-fail")
        return false
    end

    -- skip port
    if M.payload_readable_len(payload) < 2 then
        util.log_debug("mc_handshake: missing port bytes")
        return false
    end
    payload[2] = payload[2] + 2

    -- read state
    local state = M.payload_read_varint(payload, 2, false)
    util.log_debug("mc_handshake: state=" .. tostring(state))
    if state ~= 1 and state ~= 2 then
        util.log_debug("mc_handshake: illegal state, fast-fail")
        return false
    end

    -- trim suffix after \0
    if type(hostname) ~= "string" then
        return false
    end
    hostname = hostname:gsub("%z.*$", "")
    util.log_debug(string_format(
        "mc_handshake: SUCCESS proto=%s host=%s state=%s",
        tostring(protocol_version), tostring(hostname), tostring(state)
    ))
    return true, protocol_version, hostname, state
end

return M
