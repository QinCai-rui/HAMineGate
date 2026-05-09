# TODO List

1. DONE: logging IP addresses that have attempted to connect while server is down (ie. clients that conencted to this server): implemented in src/motd_server.lua
2. async handling of clients (currently each client is handled synchronously, which means if one client takes a long time to send data, it can block others...., altho i have a 2-second timeout on all socket operations to mitigate this)
3. DONE: motd_server.lua now caches the motd & disconnect message and refreshes them every 30secs or so, so clients see a stable message within each window.
4. DONE: moved blocked-IP and hostname policy checks into `src/minecraft_prot.lua`, configured by `src/blocked_ips.txt` and `src/allowed_hostnames.txt`.
