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
local string_byte = string.byte
local string_format = string.format
local table_concat = table.concat

-- Toggle verbose handshake logs for debugging only so terminal doesn't get spammed.
local DEBUG = false

local M = {}

function M.log_debug(msg)
    if DEBUG then
        core.Info(msg)
    end
end

function M.trim(text)
    return (text:gsub("^%s+", ""):gsub("%s+$", ""))
end

function M.load_lines(path)
    local entries = {}
    local file = io.open(path, "r")

    if not file then
        M.log_debug("policy: unable to open " .. path .. ", using empty list")
        return entries
    end

    for line in file:lines() do
        line = M.trim(line)
        if line ~= "" and not line:match("^#") then
            entries[#entries + 1] = line
        end
    end

    file:close()
    return entries
end

function M.list_to_set(lines, normalize)
    local set = {}
    for _, line in ipairs(lines) do
        local key = normalize and normalize(line) or line
        if key ~= "" then
            set[key] = true
        end
    end
    return set
end

function M.hexdump(s, max)
    max = max or 128
    local out = {}
    local len = string_len(s)
    if len > max then len = max end
    for i = 1, len do
        out[#out+1] = string_format("%02X", string_byte(s, i))
    end
    return table_concat(out, " ")
end

return M
