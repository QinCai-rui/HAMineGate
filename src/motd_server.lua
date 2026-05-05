-- THIS IS A STANDALONE LUA FILE, not MEANT TO BE USED AS A MODULE.
-- It implements a 'fake' Minecraft server that responds to ping requests with a periodically refreshed MOTD and disconnects login attempts with a periodically refreshed message.
-- Used as fallback in haproxy, when real backend is offline
--
-- This:
-- 1. Listens for incoming Minecraft client connections (handshake protocol)
-- 2. Reads the handshake packet to determine what the client wants (STATUS or LOGIN)
-- 3. If STATUS (1): responds with a cached MOTD that refreshes periodically
-- 4. If LOGIN (2): responds with a cached disconnect message that refreshes periodically
-- 5. Closes the connection after handling

-- It also logs login attempts with prot. version, hostname used, and timestamp.

-- Protocol decoding/handling adapted from minecraft_prot.lua, which in turn was adapted from the original HAProxy Minecraft handshake decoder. 
-- See `minecraft_prot.lua` for more info.

--[[
  This file is part of HAMineGate.
  Copyright (C) 2026 Raymont Qin
  https://github.com/QinCai-rui/HAMineGate

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU Affero General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Affero General Public License for more details.

  You should have received a copy of the GNU Affero General Public License
  along with this program. If not, see <https://www.gnu.org/licenses/>.
--]]

--#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#
-- CONFIGURE HOST AND PORT HERE!!!!-#-#
local HOST = "127.0.0.1"            --#
local PORT = 25566                  --#
--#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

local socket = require("socket")
-- seed for rng
math.randomseed(os.time())

-- LOGGING CONFIGURE
-- set ENABLE_LOGGING to false to disable ALL logging
-- set LOG_STATUS_REQUESTS / LOG_LOGIN_ATTEMPTS to control which request types get logged
-- status requests are what i call "server list pings"
-- login attempts are when clients actually try to join a sevrer.
local ENABLE_LOGGING = true
local LOG_STATUS_REQUESTS = true
local LOG_LOGIN_ATTEMPTS = true

-- use a log file
-- why did i not use syslog or some other log daemon? 
-- this is supposed to run on a very minimal system (my router in this case) and i did not want to 
local LOG_PATH = "/root/motd_server.log"

-- MOTD POOL
-- Pool of Message-Of-The-Day responses in JSON format
-- Each MOTD is a valid Minecraft server status response JSON

--[[ 
NOTE:
- version.name is what shows up as the server version in the Minecraft server list
- version.protocol (-1) is not a real Minecraft protocol version
- Because no real client supports protocol -1, it shows "Incompatible Version" in the (multiplayer) server list
- This makes it very clear to players that the server is offline
- players.max and players.online are set to 0 (no one can join)

This "hack" is inspired by services like Aternos

>> CHECK EXAMPLE SCREENSHOTS HERE: https://github.com/QinCai-rui/HAMineGate/tree/main/assets/offline-pingreq <<
--]]

local motds = {
    [[
{
  "version": {"name": "● Offline", "protocol": -1},
  "players": {"max": 0, "online": 0},
  "description": {"text": "§e§lService Paused\n§7Our servers are taking a strategic coffee break"}
}
]],
    [[
{
  "version": {"name": "● Offline", "protocol": -1},
  "players": {"max": 0, "online": 0},
  "description": {"text": "§c§lServer Offline\n§7Maintenance underway. Grab a drink"}
}
]],
    [[
{
  "version": {"name": "● Offline", "protocol": -1},
  "players": {"max": 0, "online": 0},
  "description": {"text": "§e§lTemporary Downtime\n§7The server insisted it was 'for productivity'"}
}
]],
    [[
{
  "version": {"name": "● Offline", "protocol": -1},
  "players": {"max": 0, "online": 0},
  "description": {"text": "§6§lSystem Offline\n§7Server is applying updates it definitely asked for"}
}
]],
    [[
{
  "version": {"name": "● Offline", "protocol": -1},
  "players": {"max": 0, "online": 0},
  "description": {"text": "§c§lServer Offline\n§7It saw one packet too many and simply passed away"}
}
]]
}

--[[ 
    DISCONNECT MESSAGE POOL
    Random disconnect messages shown when clients attempt to login
    These messages tell clients that the backend server is down
--]]
local disconnect_msgs = {
    "§cServer is restarting.\n§7Apparently it couldn’t handle *one* more login.",
    "§cConnection denied.\n§7The server is busy restarting. Your timing, as always, is impeccable.",
    "§cBackend unreachable.\n§7Velocity is offline or restarting.",
    "§cCannot login.\n§7The system encountered an error. It refuses to elaborate.",
    "§cSession terminated.\n§7The server has decided it’s had enough productivity for one day."
}

-- function to pick a random element from a list
-- to randomly select MOTDs and disconnect messages
local function pick(list)
    return list[math.random(#list)]
end

local MOTD_REFRESH_SECONDS = 30

local motd_cache = {
    value = nil,
    expires_at = 0,
}

local disconnect_msg_cache = {
    value = nil,
    expires_at = 0,
}

local function get_cached_random(list, cache, ttl_seconds)
    local now = os.time()
    if not cache.value or now >= cache.expires_at then
        cache.value = pick(list)
        cache.expires_at = now + ttl_seconds
    end

    return cache.value
end

local function get_cached_motd()
    local motd = get_cached_random(motds, motd_cache, MOTD_REFRESH_SECONDS)
    motd = motd:gsub("\r\n", "\n")      -- Convert Windows line endings
    motd = motd:gsub("^\n+", "")        -- Remove leading newlines
    motd = motd:gsub("\n+$", "")        -- Remove trailing newlines
    return motd
end

local function get_cached_disconnect_msg()
    return get_cached_random(disconnect_msgs, disconnect_msg_cache, MOTD_REFRESH_SECONDS)
end

local function make_connection(client)
    return {
        client = client,
        buffer = "",
    }
end

local function fill_buffer(conn, needed)
    while #conn.buffer < needed do
        local chunk, err, partial = conn.client:receive(needed - #conn.buffer)
        if chunk and #chunk > 0 then
            conn.buffer = conn.buffer .. chunk
        elseif partial and #partial > 0 then
            conn.buffer = conn.buffer .. partial
            return nil, err
        else
            return nil, err
        end
    end

    return true
end

local function read_byte(conn)
    if #conn.buffer > 0 then
        local byte = conn.buffer:sub(1, 1)
        conn.buffer = conn.buffer:sub(2)
        return byte
    end

    return conn.client:receive(1)
end

local function read_bytes(conn, count)
    local chunks = {}
    for i = 1, count do
        local byte = read_byte(conn)
        if not byte then
            return nil
        end
        chunks[i] = byte
    end

    return table.concat(chunks)
end

local function read_line(conn)
    local chunks = {}
    while true do
        local byte = read_byte(conn)
        if not byte then
            return nil
        end

        chunks[#chunks + 1] = byte
        local len = #chunks
        if len >= 2 and chunks[len - 1] == "\r" and chunks[len] == "\n" then
            return table.concat(chunks, "", 1, len - 2)
        end
    end
end

-- END functions written with help from AI

--[[ 
    VARINT ENCODING
    Minecraft protocol uses variable-length integers for efficiency i believe
    Encodes a number as 1-5 bytes with continuation bits
    each byte: bit 7 = continuation flag, bits 0-6 = data
    EG: 300 = [0xAC, 0x02] (172, 2 in decimal)
--]]
local function write_varint(num)
    local out = {}
    while true do
        local temp = num % 128  -- Extract lower 7 bits
        num = math.floor(num / 128)  -- Shift right by 7 bits
        if num > 0 then 
            temp = temp + 128  -- Set continuation bit (bit 7) if more bytes follow
        end
        table.insert(out, string.char(temp))
        if num == 0 then break end
    end
    return table.concat(out)
end

--[[ 
    VARINT DECODING
    Reads varints from the client connection
    Reads bytes until *bit 7* is not set
--]]
local function read_varint(conn)
    local num, shift = 0, 0
    while true do
        local b = read_byte(conn)  -- Read one byte from client
        if not b then return nil end  -- Connection closed or timeout
        local v = string.byte(b)
        num = num + ((v % 128) * (128 ^ shift))  -- Extract lower 7 bits and add to result
        if v < 128 then break end  -- No continuation bit, number is complete
        shift = shift + 1
    end
    return num
end

--[[ 
    READ MINECRAFT PACKET
    Minecraft packets are prefixed with a varint indicating their length
    Format: [packet_length_varint][packet_data]
--]]
local function read_packet(conn)
    local length = read_varint(conn)  -- Read packet length
    if not length then return nil end  -- Failed to read (timeout or disconnect)
    return read_bytes(conn, length)  -- Read exactly 'length' bytes
end

--[[ 
    READ HANDSHAKE PACKET
    First packet sent by Minecraft client to initiate connection
    Format: [packet_id: varint] [protocol_version: varint] [server_host: string] [server_port: ushort] [next_state: varint]
    next_state: 1 = STATUS (multiplayer server list ping), 2 = LOGIN (login attempt)
--]]
local function read_handshake(conn)
    local data = read_packet(conn)
    if not data then return nil end

    local idx = 1
    -- Local helper to read varints directly from packet buffer (instead of from socket)
    local function read_varint_from()
        local num, shift = 0, 0
        while true do
            local v = data:byte(idx)
            idx = idx + 1
            num = num + ((v % 128) * (128 ^ shift))
            if v < 128 then break end
            shift = shift + 1
        end
        return num
    end

    local packet_id = read_varint_from()  -- Should be 0x00 for handshake
    local proto = read_varint_from()  -- Minecraft protocol version number

    -- read server hostname (string format: [length_varint][string_bytes])
    local host_len = read_varint_from()
    local host = data:sub(idx, idx + host_len - 1)
    idx = idx + host_len

    idx = idx + 2  -- Skip port (2 bytes, bigendian short)

    local next_state = read_varint_from()  -- 1 = STATUS, 2 = LOGIN
    return next_state, proto, host
end

--[[ 
    BUILD DISCONNECT MESSAGE JSON
    Formats a disconnect message with additional debug information
    Includes protocol version, target host, and timestamp for interested people & myself
--]]
local function build_disconnect_json(base_msg, proto, host)
    local ts = os.date("%Y-%m-%d %H:%M:%S")
    return string.format(
        '{"text":"%s\\n\\n§7Protocol: %d\\nHost: %s\\nTime: %s"}',
        base_msg, proto or -1, host or "unknown", ts
    )
end

local function write_log(line)
    if not ENABLE_LOGGING then
        return
    end

    local file = io.open(LOG_PATH, "a")
    if file then
        file:write(line, "\n")
        file:close()
    end

    print(line)
end

local function log_status_request(peer_ip, peer_port, proto, host)
    if not LOG_STATUS_REQUESTS then
        return
    end

    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local line = string.format(
        "[%s] server list ping from %s:%s proto=%s host=%s",
        timestamp,
        tostring(peer_ip or "unknown"),
        tostring(peer_port or "unknown"),
        tostring(proto or -1),
        tostring(host or "unknown")
    )

    write_log(line)
end

local function log_login_attempt(peer_ip, peer_port, proto, host)
    if not LOG_LOGIN_ATTEMPTS then
        return
    end

    -- TODO: consider changing the date format. might be a bit too long and cluttered right now, at least IMO
    local timestamp = os.date("%Y-%m-%d %H:%M:%S")
    local line = string.format(
        "[%s] login attempt from %s:%s proto=%s host=%s",
        timestamp,
        tostring(peer_ip or "unknown"),
        tostring(peer_port or "unknown"),
        tostring(proto or -1),
        tostring(host or "unknown")
    )

    write_log(line)
end

--[[ 
    SEND LOGIN DISCONNECT PACKET
    Responds to login attempts with a disconnect message
    Packet structure: [packet_length] [packet_id: 0x00] [message_length] [message_json]
--]]
local function send_login_disconnect(conn, proto, host)
    local base = get_cached_disconnect_msg()  -- Select cached disconnect message
    local msg = build_disconnect_json(base, proto, host)  -- Build full JSON message

    -- Build login disconnect packet (packet id 0x00)
    local payload = write_varint(#msg) .. msg  -- Message as: [length_varint][json_text]
    local packet = write_varint(0x00) .. payload  -- Prepend packet id
    local full = write_varint(#packet) .. packet  -- Prepend packet length

    conn.client:send(full)
    socket.sleep(0.1)
end

--[[ 
    HANDLE STATUS REQUEST (server list ping)
    When client opens the multiplayer server list menu, or click on the Refresh button there, it sends a status request
    We respond with a MOTD and then handle the ping and pong
--]]
local function handle_status(conn)
    -- Step 1: Read status request packet
    -- Format: [packet_id: 0x00] (no additional data)
    local req = read_packet(conn)
    if not req then return end

    -- check: verify packet id is 0x00 (status request)
    local pid = string.byte(req, 1)
    if pid ~= 0x00 then
        -- Unexpected packet id, abort
        return
    end

    -- Step 2: Select cached MOTD and normalide formatting
    local motd = get_cached_motd()

    -- Step 3: Build and send status response packet
    -- Format: [packet_id: 0x00] [json_length_varint] [json_text]
    local payload =
        write_varint(0x00) ..      -- packet id for status response
        write_varint(#motd) ..     -- JSON string length in bytes
        motd                       -- JSON text with MOTD data

    local packet = write_varint(#payload) .. payload
    conn.client:send(packet)

    -- Step 4: Read ping packet from client
    -- Format: [packet_id: 0x01] [payload: 8 bytes]
    -- The 8-byte payload is typically a timestamp that we echo back
    local ping = read_packet(conn)
    if not ping then return end

    -- Verify packet id is 0x01 (ping request)
    local ping_pid = string.byte(ping, 1)
    if ping_pid ~= 0x01 then
        -- Not a ping packet, abort
        return
    end

    -- Extract the 8-byte payload (client's timestamp)
    local payload_bytes = ping:sub(2)

    -- Step 5: Build and send pong response
    -- Format: [packet_id: 0x01] [payload: echo of client's 8 bytes]
    local pong_payload =
        write_varint(0x01) ..      -- packet id for pong
        payload_bytes              -- echo the client's payload

    local pong_packet =
        write_varint(#pong_payload) ..
        pong_payload

    conn.client:send(pong_packet)
end

-- HANDLE INDIVIDUAL CLIENT CONNECTION
-- TODO: async, ip logging
-- Main logic: read handshake, determine what client wants (status or login), then respond
local function handle_client(client)
    -- Set 2-second timeout for all socket operations so we don't hang for any reason
    client:settimeout(2)

    local conn = make_connection(client)
    local sock_ip, sock_port = client:getpeername()
    local peer_ip, peer_port = sock_ip, sock_port

    -- Step 1: Read handshake packet to determine what the client wants
    local next_state, proto, host = read_handshake(conn)
    if not next_state then 
        client:close() 
        return 
    end

    if next_state == 1 then
        -- STATUS REQUEST: Client is checking server in the list (server.ping/motd)
        log_status_request(peer_ip, peer_port, proto, host)
        handle_status(conn)
        client:close()
        return
    end

    if next_state == 2 then
        -- LOGIN ATTEMPT: Client is trying to actually join the server
        -- Since backend is offline, we send a disconnect message
        log_login_attempt(peer_ip, peer_port, proto, host) -- log the attempt
        read_packet(conn)  -- Consume the login start packet
        send_login_disconnect(conn, proto, host)  -- Send disconnect message
        client:close()  -- Client sees "Connection lost" or "Disconnected" with our message
        return
    end
end

local server = assert(socket.bind(HOST, PORT))
print("Fake MOTD server running on " .. HOST .. ":" .. PORT)

-- Each connection is processed *SYNCHRONOUSLY*. TODO
while true 
do
    local client = server:accept() -- wait for client connection
    handle_client(client)  -- process the connection
end
