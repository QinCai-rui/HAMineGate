# SysVinit service file

This init script runs the standalone `haminegate` wrapper at
`/usr/local/bin/haminegate`.
It follows the LSB init script convention and works on any system with a sysv-compatible init.

## Installation

Place `haminegate` (the wrapper) in `/usr/local/bin/` and make executable:

```bash
chmod +x /usr/local/bin/haminegate
```

Place the init script in `/etc/init.d/` and make executable:

```bash
chmod +x /etc/init.d/haminegate
```

Register with the init system (if needed):

```bash
# Debian
update-rc.d haminegate defaults

# RHEL
chkconfig --add haminegate
```

## Usage

```bash
service haminegate start|stop|restart|status|check
```

## Overrides

Override the wrapper path by setting `HAMINEGATE_WRAPPER`:

```bash
HAMINEGATE_WRAPPER=/opt/bin/haminegate service haminegate start
```
