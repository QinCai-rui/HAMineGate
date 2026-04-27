-- TODO: logging IP addresses that have attempted to connect while server is down (ie. clients that conencted to this server)

-- THIS IS A STANDALONE LUA FILE, not MEANT TO BE USED AS A MODULE.
-- It implements a 'fake' Minecraft server that responds to ping requests with random MOTDs and disconnects login attempts with random messages.
-- Used as fallback in haproxy, when real backend is offline

-- Protocol decoding/handling adapted from minecraft_prot.lua

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

-----------------------------------
-- CONFIGURE HOST AND PORT HERE!!!!
local HOST = "localhost"
local PORT = 25566
-----------------------------------

local socket = require("socket")
math.randomseed(os.time())

-- MOTD pool
--[[ NOTE:
version.name is what shows up as the server version in the Minecraft server list. 
version.protocol is the protocol version number (-1 is not a real Minecraft protocol version)

since there is no real client that supports protocol version -1, 
it will show up as "Imcompatible Version", while also showing the Offline version.name

>> CHECK EXAMPLE SCREENSHOTS HERE: https://github.com/QinCai-rui/HAMineGate/tree/main/assets/offline-pingreq <<

this hack is inspired by Aternos and other services

and obviously, the actual description.text is made by Microslop Copilot. 
]]

local motds = {
    [[
{
  "version": {"name": "● Offline", "protocol": -1},
  "players": {"max": 0, "online": 0},
  "description": {"text": "§c§lService Paused\n§7Our servers are taking a strategic coffee break"}
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

-- disconnect messages pool
local disconnect_msgs = {
    "§cServer is restarting.\n§7Apparently it couldn’t handle *one* more login.",
    "§cConnection denied.\n§7The server is busy restarting. Your timing, as always, is impeccable.",
    "§cBackend unreachable.\n§7Velocity is offline or restarting.",
    "§cCannot login.\n§7The system encountered an error. It refuses to elaborate.",
    "§cSession terminated.\n§7The server has decided it’s had enough productivity for one day."
}

local function pick(list)
    return list[math.random(#list)]
end

local function write_varint(num)
    local out = {}
    while true do
        local temp = num % 128
        num = math.floor(num / 128)
        if num > 0 then temp = temp + 128 end
        table.insert(out, string.char(temp))
        if num == 0 then break end
    end
    return table.concat(out)
end

local function read_varint(client)
    local num, shift = 0, 0
    while true do
        local b = client:receive(1)
        if not b then return nil end
        local v = string.byte(b)
        num = num + ((v % 128) * (128 ^ shift))
        if v < 128 then break end
        shift = shift + 1
    end
    return num
end

local function read_packet(client)
    local length = read_varint(client)
    if not length then return nil end
    return client:receive(length)
end

local function read_handshake(client)
    local data = read_packet(client)
    if not data then return nil end

    local idx = 1
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

    local packet_id = read_varint_from()
    local proto = read_varint_from()

    local host_len = read_varint_from()
    local host = data:sub(idx, idx + host_len - 1)
    idx = idx + host_len

    idx = idx + 2 -- port

    local next_state = read_varint_from()
    return next_state, proto, host
end

local function build_disconnect_json(base_msg, proto, host)
    local ts = os.date("%Y-%m-%d %H:%M:%S")
    return string.format(
        '{"text":"%s\\n\\n§7Protocol: %d\\nHost: %s\\nTime: %s"}',
        base_msg, proto or -1, host or "unknown", ts
    )
end

local function send_login_disconnect(client, proto, host)
    local base = pick(disconnect_msgs)
    local msg = build_disconnect_json(base, proto, host)

    local payload = write_varint(#msg) .. msg
    local packet = write_varint(0x00) .. payload
    local full = write_varint(#packet) .. packet

    client:send(full)
    socket.sleep(0.1)
end

-- Handle STATUS state (server list ping)
local function handle_status(client)
    -- Read status request packet (should just be packet id 0x00)
    local req = read_packet(client)
    if not req then return end

    -- Optional sanity check: first byte should be 0x00 (packet id)
    local pid = string.byte(req, 1)
    if pid ~= 0x00 then
        -- Unknown status packet, ignore
        return
    end

    -- Pick and normalise MOTD JSON
    local motd = pick(motds)
    motd = motd:gsub("\r\n", "\n")
    motd = motd:gsub("^\n+", "")   -- strip leading newlines
    motd = motd:gsub("\n+$", "")   -- strip trailing newlines

    -- Build status response: packet id 0x00 + JSON string
    local payload =
        write_varint(0x00) ..      -- packet id
        write_varint(#motd) ..     -- JSON length in bytes
        motd                       -- JSON text

    local packet = write_varint(#payload) .. payload
    client:send(packet)

    -- Read ping packet (packet id 0x01 + 8-byte payload)
    local ping = read_packet(client)
    if not ping then return end

    local ping_pid = string.byte(ping, 1)
    if ping_pid ~= 0x01 then
        -- Not a ping packet, ignore
        return
    end

    local payload_bytes = ping:sub(2) -- the 8-byte payload

    -- Build pong: packet id 0x01 + same payload
    local pong_payload =
        write_varint(0x01) ..
        payload_bytes

    local pong_packet =
        write_varint(#pong_payload) ..
        pong_payload

    client:send(pong_packet)
end

local function handle_client(client)
    client:settimeout(2)

    local next_state, proto, host = read_handshake(client)
    if not next_state then client:close() return end

    if next_state == 1 then
        -- STATUS REQUEST
        handle_status(client)
        client:close()
        return
    end

    if next_state == 2 then
        -- LOGIN ATTEMPT
        read_packet(client)
        send_login_disconnect(client, proto, host)
        client:close()
        return
    end
end

local server = assert(socket.bind(HOST, PORT))
print("Fake MOTD server running on " .. HOST .. ":" .. PORT)

while true do
    local client = server:accept()
    handle_client(client)
end
