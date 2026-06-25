-- HAMineGate configuration
-- This file is loaded by minecraft_prot_policy.lua and motd_server.lua.
-- Place it in the same directory as the other haminegate Lua files.

local config = {
    -- Verbose HAProxy debug logs (hex dumps, parsed fields)
    debug = false,

    -- MOTD server listen address and port
    listen_host = "127.0.0.1",
    listen_port = 25566,

    -- Log file path (motd_server.lua)
    log_path = "/root/motd_server.log",

    -- Log verbosity
    log_status_requests = true,
    log_login_attempts = true,

    -- MOTD refresh interval (seconds)
    motd_refresh_seconds = 30,

    -- Blocked source IPs (lowercase, matched exactly against client IP)
    blocked_ips = {
        "172.66.147.243",
        "104.20.23.154",
    },

    -- Allowed hostnames / domain suffixes.
    -- Supports:
    --   exact match:   mc.example.com
    --   wildcard:      *.example.com
    --   suffix match:  example.com  (matches mc.example.com, proxy.example.com, etc.)
    -- Matching is case-insensitive.
    allowed_hostnames = {
        "*.mc.qincai.xyz",
        "mc.qincai.xyz",
        "2407:7000:f030:c684::1",
    },

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
    motds = {
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
]],
    },

    -- Disconnect message pool (randomly selected for login attempts)
    disconnect_msgs = {
        "§cServer is restarting.\n§7Apparently it couldn't handle *one* more login.",
        "§cConnection denied.\n§7The server is busy restarting. Your timing, as always, is impeccable.",
        "§cBackend unreachable.\n§7Velocity is offline or restarting.",
        "§cCannot login.\n§7The system encountered an error. It refuses to elaborate.",
        "§cSession terminated.\n§7The server has decided it's had enough productivity for one day.",
    },
}

return config
