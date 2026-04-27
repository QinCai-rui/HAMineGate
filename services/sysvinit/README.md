# SysVinit service files

`haproxy` should be placed in `/etc/init.d/` and made executable (`chmod +x /etc/init.d/haproxy`).

Then you can use `service haproxy start|stop|restart|status` to manage the service, check the configuration with `service haproxy check`. You may also want to enable it on boot with `update-rc.d haproxy enable`.