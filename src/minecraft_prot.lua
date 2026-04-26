-- THIS IS NOT A STANDALONE LUA FILE, BUT MEANT TO BE USED AS A MODULE.

--[[
  MIT LICENSE
  Copyright 2026 Raymont Qin
  https://github.com/QinCai-rui/HAMineGate
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

-- This file is a *heavily* modified version of the original HAProxy Lua script for decoding Minecraft handshakes. 
-- It was made for a whole different purpose, and there were few issues.
-- ORIGINAL LICENSE below:

--[[
  This script is a Lua file for decoding the Minecraft handshake (protocol
  version, hostname, next-state) with HAProxy to choose which backend to use.
  https://gist.github.com/nathan818fr/a078e92604784ad56e84843ebf99e2e5
--
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

local string_len  = string.len
local string_byte = string.byte
local string_sub  = string.sub
local string_find = string.find

-- Toggle verbose handshake logs for debugging only so terminal doesn't get spammed.
local DEBUG = false

local function log_debug(msg)
    if DEBUG then
        core.Info(msg)
    end
end

-- Returns the number of readable bytes in this payload.
local function payload_readable_len(payload)
    return string_len(payload[1]) - payload[2] + 1
end

-- Gets a VarInt at the current reader_index and increases the reader_index by its length.
local function payload_read_varint(payload, max_bytes, nilable)
    local ret   = 0
    local bytes = 0
    local b
    while true do
        b = string_byte(payload[1], payload[2] + bytes)
        if b == nil then
            if nilable then
                -- missing data, let caller know
                return
            else
                -- fail (missing data)
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
local function payload_read_string(payload, max_prefix_bytes, max_utf8_len)
    local str_len = payload_read_varint(payload, max_prefix_bytes, false)
    if (str_len == -1 or str_len > max_utf8_len or str_len > payload_readable_len(payload)) then
        return false
    end
    local str = string_sub(payload[1], payload[2], payload[2] + str_len - 1)
    payload[2] = payload[2] + str_len
    return str
end

-- Hex dump helper for debugging
local function hexdump(s, max)
    max = max or 128
    local out = {}
    local len = string_len(s)
    if len > max then len = max end
    for i = 1, len do
        out[#out+1] = string.format("%02X", string_byte(s, i))
    end
    return table.concat(out, " ")
end

-- Decode the minecraft handshake packet.
local function read_mc_handshake(payload)
    if payload[1] == nil then
        log_debug("mc_handshake: no payload yet")
        return
    end

    log_debug(string.format(
        "mc_handshake: raw_len=%d readable=%d hex=%s",
        string_len(payload[1]),
        payload_readable_len(payload),
        hexdump(payload[1])
    ))

    -- read packet len
    local packet_len = payload_read_varint(payload, 3, true)
    log_debug("mc_handshake: packet_len=" .. tostring(packet_len))
    if packet_len == nil then
        log_debug("mc_handshake: need more data for packet_len")
        return
    end
    if packet_len == -1 or packet_len > 4096 then
        log_debug("mc_handshake: invalid packet_len, fast-fail")
        return false
    end
    if packet_len > payload_readable_len(payload) then
        log_debug("mc_handshake: incomplete packet, waiting more data")
        return
    end

    -- read packet id (for handshakes this must be 0)
    local packet_id = payload_read_varint(payload, 3, false)
    log_debug("mc_handshake: packet_id=" .. tostring(packet_id))
    if packet_id == -1 or packet_id ~= 0 then
        log_debug("mc_handshake: invalid packet_id")
        return false
    end

    -- read protocol version
    local protocol_version = payload_read_varint(payload, 5, false)
    log_debug("mc_handshake: protocol_version=" .. tostring(protocol_version))
    if protocol_version == -1 or protocol_version <= 0 then
        log_debug("mc_handshake: illegal protocol_version, fast-fail")
        return false
    end

    -- read hostname
    local hostname = payload_read_string(payload, 3, 255)
    log_debug("mc_handshake: hostname_raw=" .. tostring(hostname))
    if hostname == false then
        log_debug("mc_handshake: illegal hostname, fast-fail")
        return false
    end

    -- skip port
    if payload_readable_len(payload) < 2 then
        log_debug("mc_handshake: missing port bytes")
        return false
    end
    payload[2] = payload[2] + 2

    -- read state
    local state = payload_read_varint(payload, 2, false)
    log_debug("mc_handshake: state=" .. tostring(state))
    if state ~= 1 and state ~= 2 then
        log_debug("mc_handshake: illegal state, fast-fail")
        return false
    end

    -- trim suffix after \0
    local host_end = string_find(hostname, '\0', 1, true)
    if host_end ~= nil then
        hostname = string_sub(hostname, 1, host_end - 1)
    end
    log_debug(string.format(
        "mc_handshake: SUCCESS proto=%s host=%s state=%s",
        tostring(protocol_version), tostring(hostname), tostring(state)
    ))
    return true, protocol_version, hostname, state
end

-- HAProxy action
local function mc_handshake(txn)
    local raw = txn.req:dup()
    log_debug(string.format("mc_handshake: txn.req.len=%d", string_len(raw or "")))

    local res, proto, host, state = read_mc_handshake({ raw, 1 })
    log_debug(string.format("mc_handshake: result=%s proto=%s host=%s state=%s",
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
    end
end

core.register_action('mc_handshake', { 'tcp-req' }, mc_handshake, 0)
