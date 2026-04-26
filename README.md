# HAMineGate

## Why implement a hostname allowlist

See the protocol notes for a shorter version: [Protocol (Overview)](docs/PROTOCOL.md#overview)

By checking the hostname in the handshake packet, you can implement very simple allowlists (ACL in `haproxy.cfg`) without needing complex authentication or backend logic. For example, you might only want to allow connections that use your official hostname in the handshake packet (in my case, any subdomains of `mc.qincai.xyz`), or block certain IP-based hostnames.

I originally wanted this because I was seeing a lot of traffic from `slowstack.tv`, a Minecraft server prober that scans IP ranges for open Minecraft servers, and other random traffic from around the world. I can (somewhat) reduce unwanted traffic by blocking connections that don't use my official domain/hostname.

By doing it at the HAProxy level, I can stop most unwanted connections before they *even* reach my backend server (Velocity), which reduces load and potential attack surface, as Velocity uses much more resources to handle a connection than HAProxy does. (and also I have to install plugins, assuming they even exist, on Velocity to do hostname-based filtering, which is *much* more work and less efficient than doing it at the HAProxy level)
