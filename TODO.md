# TODO List

1. DONE: logging IP addresses that have attempted to connect while server is down (ie. clients that conencted to this server): implemented in src/motd_server.lua

2. async handling of clients (currently each client is handled synchronously, which means if one client takes a long time to send data, it can block others...., altho i have a 2-second timeout on all socket operations to mitigate this)

3. DONE: motd_server.lua now caches the motd & disconnect message and refreshes them every 30secs or so, so clients see a stable message within each window.

4. right now a lot of the logic is done in haproxy.cfg, which is quite weird, maybe we can move some of the logic to the lua scripts instead, and just have haproxy.cfg call the lua scripts for certain things, like for example, instead of having haproxy.cfg check if the client is blocked or not, we can have haproxy.cfg call a lua script that checks if the client is blocked or not, and then returns the result to haproxy.cfg, which can then decide what to do based on the result. This way we can keep most of the logic in the lua scripts, which is more flexible and easier to maintain than having a lot of logic in haproxy.cfg. also from a legal perspective, afaik, im not allowed to put a license on config files. so... better change that ig
    1. implement a more robust way to handle blocked IPs, maybe we can have a separate file that contains the blocked IPs, and then have a lua script that reads that file and checks if the client IP is in that file or not. This way we can easily add or remove blocked IPs without having to modify the haproxy.cfg file, which can be a bit tricky to edit for some people.
    2. ^^, but do the same with allowed hostnames in a txt file, then have the same lua scirpt read that file and check if the hostname is in that file or not, and then return the result to haproxy.cfg, which can then decide what to do based on the result. this would make it much much easier to add or remove allowed hostnames without having to modify the haproxy.cfg file.

