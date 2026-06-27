#!/bin/sh

set -e

# =============================================================================
#  HAMineGate Installer — interactive
#  Requires only: curl, sh (POSIX)
#
#  Usage:
#    curl -sSfL https://raw.githubusercontent.com/QinCai-rui/HAMineGate/main/install.sh | sh
#    curl ... | sh -s -- --haproxy-dir /etc/haproxy
#    HAPROXY_DIR=/etc/haproxy ./install.sh
#
#  Flags override prompts. When run interactively you'll be asked for
#  directories and for each existing file.
# =============================================================================

# This script is largely written by DeepSeek.

# ---- ANSI colours ----
R='\033[0;31m'     G='\033[0;32m'     Y='\033[1;33m'
B='\033[0;34m'     C='\033[0;36m'     M='\033[0;35m'
BOLD='\033[1m'     NC='\033[0m'

info()  { printf "${C}  ->${NC} %b\n" "$*"; }
ok()    { printf "${G}  [OK]${NC} %b\n" "$*"; }
warn()  { printf "${Y}  [WARN]${NC} %b\n" "$*"; }
err()   { printf "${R}  [ERR]${NC} %b\n" "$*"; }
title() { printf "\n${BOLD}${B}==>${NC}${BOLD} %b${NC}\n" "$*"; }
sub()   { printf "  ${C}::${NC} %b\n" "$*"; }
# ---- END ANSI colours ----

# ---- Defaults ----
HAPROXY_DIR="${HAPROXY_DIR:-/root/haproxy}"
WRAPPER_DIR="${WRAPPER_DIR:-/usr/local/bin}"
SYSTEMD_DIR="${SYSTEMD_DIR:-/etc/systemd/system}"
INSTALL_SYSTEMD=0
BRANCH="${BRANCH:-main}"
BASE_URL="${BASE_URL:-https://raw.githubusercontent.com/QinCai-rui/HAMineGate/$BRANCH}"
DRY_RUN=0
FORCE=0
LOCAL=0
REPO_DIR=""
NONINTERACTIVE=0

# ---- Help ----
usage() {
    cat <<EOF
${BOLD}HAMineGate Installer${NC}

${BOLD}Usage:${NC}
  ${C}curl -sSfL https://raw.githubusercontent.com/QinCai-rui/HAMineGate/main/install.sh | sh${NC}
  ${C}curl ... | sh -s -- --haproxy-dir /etc/haproxy --force${NC}
  ${C}HAPROXY_DIR=/etc/haproxy ./install.sh${NC}

${BOLD}Flags:${NC}
  --haproxy-dir DIR   Lua scripts & config destination  [default: $HAPROXY_DIR]
  --wrapper-dir DIR   Wrapper script destination        [default: $WRAPPER_DIR]
  --init-dir DIR      SysVinit script destination       [default: $INIT_DIR]
  --systemd-dir DIR   systemd unit destination          [default: $SYSTEMD_DIR]
  --with-systemd      Also install the systemd unit file
  --branch NAME       Git branch to fetch from          [default: $BRANCH]
  --base-url URL      Full raw base URL (overrides --branch)
  --force             Overwrite all config/data files without asking
  --yes, -y           Skip all prompts, use defaults
  --dry-run           Show what would be done, don't act
  -h, --help          Show this help
EOF
    exit 0
}

# ---- Parse arguments ----
while [ $# -gt 0 ]; do
    case "$1" in
    --haproxy-dir)  HAPROXY_DIR="$2";  shift ;;
    --wrapper-dir)  WRAPPER_DIR="$2";  shift ;;
    --init-dir)     INIT_DIR="$2";     shift ;;
    --systemd-dir)  SYSTEMD_DIR="$2";  shift ;;
    --with-systemd) INSTALL_SYSTEMD=1 ;;
    --branch)       BRANCH="$2";       shift ;;
    --base-url)     BASE_URL="$2";     shift ;;
    --force)        FORCE=1 ;;
    --yes|-y)       NONINTERACTIVE=1 ;;
    --dry-run)      DRY_RUN=1 ;;
    -h|--help)      usage ;;
    *) err "Unknown option: $1"; usage ;;
    esac
    shift
done

# ---- Detect local installation ----
SCRIPT_DIR=""
case "$0" in
    */*) SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)" ;;
esac

if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/src/minecraft_prot.lua" ]; then
    LOCAL=1
    REPO_DIR="$SCRIPT_DIR"
elif [ -f "./src/minecraft_prot.lua" ]; then
    LOCAL=1
    REPO_DIR="$PWD"
fi

# ---- Interactive prompts (unless non-interactive or flags set) ----
HAS_FLAGS=0
[ "$HAPROXY_DIR" != "/root/haproxy" ] && HAS_FLAGS=1
[ "$WRAPPER_DIR" != "/usr/local/bin" ] && HAS_FLAGS=1
[ "$SYSTEMD_DIR" != "/etc/systemd/system" ] && HAS_FLAGS=1
[ "$INSTALL_SYSTEMD" = "1" ] && HAS_FLAGS=1
[ "$FORCE" = "1" ] && HAS_FLAGS=1

if [ "$HAS_FLAGS" = "0" ] && [ "$NONINTERACTIVE" = "0" ]; then
    # Only prompt if /dev/tty is available (piped via curl but user is at a terminal)
    if [ -c /dev/tty ] 2>/dev/null; then
        printf "\n${BOLD}${M}╔══════════════════════════╗${NC}\n"
        printf   "${BOLD}${M}║  HAMineGate  Installer   ║${NC}\n"
        printf   "${BOLD}${M}╚══════════════════════════╝${NC}\n\n"

        if [ "$LOCAL" = "1" ]; then
            sub "Source: ${C}${REPO_DIR}${NC} (local)"
        else
            sub "Source: ${C}${BASE_URL}${NC}"
        fi
        echo

        printf "  ${BOLD}Directories (press Enter to accept default)${NC}\n"

        printf "  ${C}::${NC} HAProxy scripts & config dir [${G}%s${NC}]: " "$HAPROXY_DIR"
        read -r input < /dev/tty || true
        [ -n "$input" ] && HAPROXY_DIR="$input"

        printf "  ${C}::${NC} Wrapper script dir        [${G}%s${NC}]: " "$WRAPPER_DIR"
        read -r input < /dev/tty || true
        [ -n "$input" ] && WRAPPER_DIR="$input"

        printf "  ${C}::${NC} SysVinit scripts dir       [${G}%s${NC}]: " "$INIT_DIR"
        read -r input < /dev/tty || true
        [ -n "$input" ] && INIT_DIR="$input"

        printf "  ${Y}?${NC} Install systemd unit too?  ${BOLD}[y/N]${NC} "
        read -r input < /dev/tty || true
        case "$(printf "%s" "$input" | tr '[:upper:]' '[:lower:]')" in
            y|yes) INSTALL_SYSTEMD=1 ;;
        esac

        echo
    fi
fi

# ---- File existence checks (for prompting) ----
FILE_EXISTS_HAPROXY_CFG=0
[ -f "$HAPROXY_DIR/haproxy.cfg" ] && FILE_EXISTS_HAPROXY_CFG=1

FILE_EXISTS_CONFIG=0
[ -f "$HAPROXY_DIR/haminegate_cfg.lua" ] && FILE_EXISTS_CONFIG=1

# ---- Mode decisions ----
MODE_HAPROXY_CFG="overwrite"
MODE_CONFIG="overwrite"
MODE_WRAPPER="overwrite"
MODE_INIT_SCRIPT="overwrite"
MODE_SYSTEMD="overwrite"

if [ "$FORCE" = "1" ]; then
    MODE_CONFIG="overwrite"
    MODE_WRAPPER="overwrite"
    MODE_INIT_SCRIPT="overwrite"
    MODE_SYSTEMD="overwrite"
elif [ "$NONINTERACTIVE" = "1" ]; then
    # Non-interactive: preserve existing config, install if missing
    [ "$FILE_EXISTS_CONFIG" = "1" ] && MODE_CONFIG="skip"
elif [ -c /dev/tty ] 2>/dev/null; then
    # Interactive — ask for each existing file
    if [ "$FILE_EXISTS_HAPROXY_CFG" = "1" ]; then
        printf "  ${Y}?${NC} ${HAPROXY_DIR}/haproxy.cfg exists. Backup and overwrite? ${BOLD}[Y/n]${NC} "
        read -r input < /dev/tty || true
        case "$(printf "%s" "$input" | tr '[:upper:]' '[:lower:]')" in
            n|no) MODE_HAPROXY_CFG="skip" ;;
            *)     MODE_HAPROXY_CFG="backup" ;;
        esac
    fi

    if [ "$FILE_EXISTS_CONFIG" = "1" ]; then
        printf "  ${Y}?${NC} ${HAPROXY_DIR}/haminegate_cfg.lua exists. Overwrite? ${BOLD}[y/N]${NC} "
        read -r input < /dev/tty || true
        case "$(printf "%s" "$input" | tr '[:upper:]' '[:lower:]')" in
            y|yes) MODE_CONFIG="overwrite" ;;
            *)     MODE_CONFIG="skip" ;;
        esac
    fi

    if [ -f "$WRAPPER_DIR/haminegate" ]; then
        printf "  ${Y}?${NC} ${WRAPPER_DIR}/haminegate exists. Overwrite? ${BOLD}[Y/n]${NC} "
        read -r input < /dev/tty || true
        case "$(printf "%s" "$input" | tr '[:upper:]' '[:lower:]')" in
            n|no) MODE_WRAPPER="skip" ;;
            *) ;;
        esac
    fi

    if [ -f "$INIT_DIR/haminegate" ]; then
        printf "  ${Y}?${NC} ${INIT_DIR}/haminegate (sysvinit) exists. Overwrite? ${BOLD}[Y/n]${NC} "
        read -r input < /dev/tty || true
        case "$(printf "%s" "$input" | tr '[:upper:]' '[:lower:]')" in
            n|no) MODE_INIT_SCRIPT="skip" ;;
            *) ;;
        esac
    fi

    if [ "$INSTALL_SYSTEMD" = "1" ] && [ -f "$SYSTEMD_DIR/haminegate.service" ]; then
        printf "  ${Y}?${NC} ${SYSTEMD_DIR}/haminegate.service exists. Overwrite? ${BOLD}[Y/n]${NC} "
        read -r input < /dev/tty || true
        case "$(printf "%s" "$input" | tr '[:upper:]' '[:lower:]')" in
            n|no) MODE_SYSTEMD="skip" ;;
            *) ;;
        esac
    fi
    echo
fi

# ---- Plan overview ----
printf "\n${BOLD}${B}╔══════════════════════════════════════╗${NC}\n"
printf   "${BOLD}${B}║  Installation plan                   ║${NC}\n"
printf   "${BOLD}${B}╚══════════════════════════════════════╝${NC}\n\n"

if [ "$LOCAL" = "1" ]; then
    sub "Source: ${C}${REPO_DIR}${NC}"
else
    sub "Source: ${C}${BASE_URL}${NC}"
fi
echo

sub "${BOLD}Lua modules → ${C}${HAPROXY_DIR}/${NC}"
for f in minecraft_prot.lua minecraft_prot_util.lua minecraft_prot_policy.lua minecraft_prot_parser.lua motd_server.lua; do
    if [ -f "$HAPROXY_DIR/$f" ]; then
        info "$f (${Y}will overwrite${NC})"
    else
        info "$f"
    fi
done

echo
sub "${BOLD}Config → ${C}${HAPROXY_DIR}/${NC}"
if [ "$MODE_HAPROXY_CFG" = "skip" ]; then
    info "haproxy.cfg (${Y}skipping${NC})"
elif [ "$MODE_HAPROXY_CFG" = "backup" ]; then
    info "haproxy.cfg (${C}backup + overwrite${NC})"
else
    info "haproxy.cfg"
fi

echo
sub "${BOLD}Config → ${C}${HAPROXY_DIR}/${NC}"
if [ "$MODE_CONFIG" = "skip" ]; then
    info "haminegate_cfg.lua (${Y}skipping, existing kept${NC})"
else
    info "haminegate_cfg.lua"
fi

echo
sub "${BOLD}Wrapper → ${C}${WRAPPER_DIR}/${NC}"
if [ "$MODE_WRAPPER" = "skip" ]; then
    info "haminegate (${Y}skipping${NC})"
else
    info "haminegate"
fi

echo
sub "${BOLD}SysVinit init script → ${C}${INIT_DIR}/${NC}"
if [ "$MODE_INIT_SCRIPT" = "skip" ]; then
    info "haminegate (${Y}skipping${NC})"
else
    info "haminegate"
fi

if [ "$INSTALL_SYSTEMD" = "1" ]; then
    echo
    sub "${BOLD}systemd unit → ${C}${SYSTEMD_DIR}/${NC}"
    if [ "$MODE_SYSTEMD" = "skip" ]; then
        info "haminegate.service (${Y}skipping${NC})"
    else
        info "haminegate.service"
    fi
fi

echo

# ---- Confirmation ----
if [ "$DRY_RUN" = "1" ]; then
    sub "${Y}*** DRY RUN — nothing was installed ***${NC}"
    echo
    exit 0
fi

if [ "$NONINTERACTIVE" = "0" ] && [ -c /dev/tty ] 2>/dev/null; then
    printf "  ${Y}?${NC} Proceed with installation? ${BOLD}[Y/n]${NC} "
    read -r input < /dev/tty || true
    case "$(printf "%s" "$input" | tr '[:upper:]' '[:lower:]')" in
        n|no)
            echo
            warn "Installation cancelled."
            echo
            exit 0
            ;;
        *) ;;
    esac
fi

# =============================================================================
#  Execute installation
# =============================================================================
echo
title "Installing Lua modules → $HAPROXY_DIR"
mkdir -p "$HAPROXY_DIR"
for f in minecraft_prot.lua minecraft_prot_util.lua minecraft_prot_policy.lua minecraft_prot_parser.lua motd_server.lua; do
    if [ "$LOCAL" = "1" ]; then
        cp "$REPO_DIR/src/$f" "$HAPROXY_DIR/$f"
    else
        curl -sSfL "$BASE_URL/src/$f" -o "$HAPROXY_DIR/$f"
    fi
    ok "$HAPROXY_DIR/$f"
done

title "Installing HAProxy config → $HAPROXY_DIR"
if [ "$MODE_HAPROXY_CFG" = "skip" ]; then
    warn "Skipping haproxy.cfg (keeping existing)"
elif [ "$MODE_HAPROXY_CFG" = "backup" ] && [ -f "$HAPROXY_DIR/haproxy.cfg" ]; then
    bak="$HAPROXY_DIR/haproxy.cfg.bak"
    n=0
    while [ -f "$bak" ]; do n=$((n + 1)); bak="$HAPROXY_DIR/haproxy.cfg.bak.$n"; done
    cp "$HAPROXY_DIR/haproxy.cfg" "$bak"
    info "Backed up existing → $bak"
    if [ "$LOCAL" = "1" ]; then
        cp "$REPO_DIR/src/haproxy.cfg" "$HAPROXY_DIR/haproxy.cfg"
    else
        curl -sSfL "$BASE_URL/src/haproxy.cfg" -o "$HAPROXY_DIR/haproxy.cfg"
    fi
    ok "$HAPROXY_DIR/haproxy.cfg"
elif [ "$MODE_HAPROXY_CFG" != "skip" ]; then
    if [ "$LOCAL" = "1" ]; then
        cp "$REPO_DIR/src/haproxy.cfg" "$HAPROXY_DIR/haproxy.cfg"
    else
        curl -sSfL "$BASE_URL/src/haproxy.cfg" -o "$HAPROXY_DIR/haproxy.cfg"
    fi
    ok "$HAPROXY_DIR/haproxy.cfg"
fi

title "Installing config → $HAPROXY_DIR"
if [ "$MODE_CONFIG" = "skip" ]; then
    warn "Skipping haminegate_cfg.lua (keeping existing)"
else
    if [ "$LOCAL" = "1" ]; then
        cp "$REPO_DIR/src/examples/haminegate_cfg.lua" "$HAPROXY_DIR/haminegate_cfg.lua"
    else
        curl -sSfL "$BASE_URL/src/examples/haminegate_cfg.lua" -o "$HAPROXY_DIR/haminegate_cfg.lua"
    fi
    ok "$HAPROXY_DIR/haminegate_cfg.lua"
fi

title "Installing wrapper → $WRAPPER_DIR"
mkdir -p "$WRAPPER_DIR"
if [ "$MODE_WRAPPER" = "skip" ]; then
    warn "Skipping haminegate wrapper (keeping existing)"
else
    if [ "$LOCAL" = "1" ]; then
        cp "$REPO_DIR/services/haminegate" "$WRAPPER_DIR/haminegate"
    else
        curl -sSfL "$BASE_URL/services/haminegate" -o "$WRAPPER_DIR/haminegate"
    fi
    chmod +x "$WRAPPER_DIR/haminegate"
    ok "$WRAPPER_DIR/haminegate"
fi

title "Installing SysVinit init script → $INIT_DIR"
mkdir -p "$INIT_DIR"
if [ "$MODE_INIT_SCRIPT" = "skip" ]; then
    warn "Skipping sysvinit init script (keeping existing)"
else
    if [ "$LOCAL" = "1" ]; then
        cp "$REPO_DIR/services/sysvinit/haminegate" "$INIT_DIR/haminegate"
    else
        curl -sSfL "$BASE_URL/services/sysvinit/haminegate" -o "$INIT_DIR/haminegate"
    fi
    chmod +x "$INIT_DIR/haminegate"
    ok "$INIT_DIR/haminegate"
fi

if [ "$INSTALL_SYSTEMD" = "1" ]; then
    title "Installing systemd unit → $SYSTEMD_DIR"
    mkdir -p "$SYSTEMD_DIR"
    if [ "$MODE_SYSTEMD" = "skip" ]; then
        warn "Skipping systemd unit (keeping existing)"
    else
        if [ "$LOCAL" = "1" ]; then
            cp "$REPO_DIR/services/systemd/haminegate.service" "$SYSTEMD_DIR/haminegate.service"
        else
            curl -sSfL "$BASE_URL/services/systemd/haminegate.service" -o "$SYSTEMD_DIR/haminegate.service"
        fi
        ok "$SYSTEMD_DIR/haminegate.service"
    fi
fi

# ---- Substitute paths in installed files if non-default dir ----
if [ "$HAPROXY_DIR" != "/root/haproxy" ]; then
    title "Updating paths in installed files → $HAPROXY_DIR"
    if [ -f "$WRAPPER_DIR/haminegate" ]; then
        sed -i "s|/root/haproxy|$HAPROXY_DIR|g" "$WRAPPER_DIR/haminegate"
        ok "Patched $WRAPPER_DIR/haminegate"
    fi
    if [ -f "$HAPROXY_DIR/haproxy.cfg" ]; then
        sed -i "s|/root/haproxy|$HAPROXY_DIR|g" "$HAPROXY_DIR/haproxy.cfg"
        ok "Patched $HAPROXY_DIR/haproxy.cfg"
    fi
fi

# =============================================================================
#  Summary
# =============================================================================
echo
printf "${BOLD}${G}╔══════════════════════════════════════════════════╗${NC}\n"
printf "${BOLD}${G}║  Installation complete                           ║${NC}\n"
printf "${BOLD}${G}╚══════════════════════════════════════════════════╝${NC}\n"
echo
printf "  ${BOLD}Lua scripts:${NC}   %b\n"  "${C}${HAPROXY_DIR}/*.lua${NC}"
printf "  ${BOLD}Config:${NC}        %b\n"  "${C}${HAPROXY_DIR}/haminegate_cfg.lua${NC}"
printf "  ${BOLD}HAProxy cfg:${NC}   %b\n"  "${C}${HAPROXY_DIR}/haproxy.cfg${NC}"
printf "  ${BOLD}Wrapper:${NC}       %b\n"  "${C}${WRAPPER_DIR}/haminegate${NC}"
printf "  ${BOLD}SysVinit:${NC}      %b\n"  "${C}${INIT_DIR}/haminegate${NC}"
if [ "$INSTALL_SYSTEMD" = "1" ]; then
    printf "  ${BOLD}systemd:${NC}       %b\n"  "${C}${SYSTEMD_DIR}/haminegate.service${NC}"
fi
echo
printf "  ${BOLD}Next steps:${NC}\n"
printf "    ${Y}1.${NC} Edit ${C}${HAPROXY_DIR}/haminegate_cfg.lua${NC} to set your blocked IPs and allowed hostnames\n"
printf "    ${Y}2.${NC} Edit ${C}${HAPROXY_DIR}/haproxy.cfg${NC} to match your backend\n"
printf "    ${Y}3.${NC} Start everything: ${C}${WRAPPER_DIR}/haminegate start${NC}\n"
echo
