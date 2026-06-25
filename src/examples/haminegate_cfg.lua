-- HAMineGate configuration
-- This file is loaded by minecraft_prot_policy.lua and motd_server.lua.
-- Place it in the same directory as the other haminegate Lua files.

local config = {
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
}

return config
