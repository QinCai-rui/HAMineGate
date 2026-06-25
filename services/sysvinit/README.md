# SysVinit service files

`haminegate` is a unified wrapper script that manages both HAProxy and the MOTD fallback server.

Place it in `/etc/init.d/` or `/usr/local/bin/` and make executable:

```bash
    chmod +x haminegate
```

Then use:

```bash
    haminegate start|stop|restart|status|check   # background service mode
    haminegate -f|--foreground                    # foreground (Ctrl+C to stop)
```

In background mode, process PIDs are tracked in `/var/run/haproxy.pid` and
`/var/run/motd-fallback.pid`.

Override the HAProxy scripts directory with `HAPROXY_DIR`:

```bash
    HAPROXY_DIR=/etc/haproxy haminegate start
```
