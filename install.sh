#!/bin/sh

set -e

# =============================================================================
#  HAMineGate Installer — interactive
#  Requires only: curl, sh (POSIX)
#
#  Usage:
#    curl -sSfL https://raw.githubusercontent.com/QinCai-rui/HAMineGate/main/install.sh | bash
#    curl ... | bash -s -- --haproxy-dir /etc/haproxy
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
INIT_DIR="${INIT_DIR:-/etc/init.d}"
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
  ${C}curl -sSfL https://raw.githubusercontent.com/QinCai-rui/HAMineGate/main/install.sh | bash${NC}
  ${C}curl ... | bash -s -- --haproxy-dir /etc/haproxy --force${NC}
  ${C}HAPROXY_DIR=/etc/haproxy ./install.sh${NC}

${BOLD}Flags:${NC}
  --haproxy-dir DIR   Lua scripts & config destination  [default: $HAPROXY_DIR]
  --init-dir DIR      Init script destination           [default: $INIT_DIR]
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
        --haproxy-dir) HAPROXY_DIR="$2"; shift ;;
        --init-dir)    INIT_DIR="$2";    shift ;;
        --branch)      BRANCH="$2";      shift ;;
        --base-url)    BASE_URL="$2";    shift ;;
        --force)       FORCE=1 ;;
        --yes|-y)      NONINTERACTIVE=1 ;;
        --dry-run)     DRY_RUN=1 ;;
        -h|--help)     usage ;;
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
[ "$INIT_DIR" != "/etc/init.d" ] && HAS_FLAGS=1
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

        printf "  ${C}::${NC} Init scripts dir           [${G}%s${NC}]: " "$INIT_DIR"
        read -r input < /dev/tty || true
        [ -n "$input" ] && INIT_DIR="$input"

        echo
    fi
fi

# ---- File existence checks (for prompting) ----
FILE_EXISTS_HAPROXY_CFG=0
[ -f "$HAPROXY_DIR/haproxy.cfg" ] && FILE_EXISTS_HAPROXY_CFG=1

FILE_EXISTS_BLOCKED=0
[ -f "$HAPROXY_DIR/blocked_ips.txt" ] && FILE_EXISTS_BLOCKED=1

FILE_EXISTS_ALLOWED=0
[ -f "$HAPROXY_DIR/allowed_hostnames.txt" ] && FILE_EXISTS_ALLOWED=1



# ---- Mode decisions ----
MODE_HAPROXY_CFG="overwrite"
MODE_BLOCKED="skip"
MODE_ALLOWED="skip"
MODE_INIT_HAPROXY="overwrite"
MODE_INIT_MOTD="overwrite"

if [ "$FORCE" = "1" ]; then
    MODE_BLOCKED="overwrite"
    MODE_ALLOWED="overwrite"
    MODE_INIT_HAPROXY="overwrite"
    MODE_INIT_MOTD="overwrite"
elif [ "$NONINTERACTIVE" = "1" ]; then
    # Non-interactive: keep defaults (data files skip, scripts/config overwrite)
    :
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

    if [ "$FILE_EXISTS_BLOCKED" = "1" ]; then
        printf "  ${Y}?${NC} ${HAPROXY_DIR}/blocked_ips.txt exists. Overwrite? ${BOLD}[y/N]${NC} "
        read -r input < /dev/tty || true
        case "$(printf "%s" "$input" | tr '[:upper:]' '[:lower:]')" in
            y|yes) MODE_BLOCKED="overwrite" ;;
            *)     MODE_BLOCKED="skip" ;;
        esac
    fi

    if [ "$FILE_EXISTS_ALLOWED" = "1" ]; then
        printf "  ${Y}?${NC} ${HAPROXY_DIR}/allowed_hostnames.txt exists. Overwrite? ${BOLD}[y/N]${NC} "
        read -r input < /dev/tty || true
        case "$(printf "%s" "$input" | tr '[:upper:]' '[:lower:]')" in
            y|yes) MODE_ALLOWED="overwrite" ;;
            *)     MODE_ALLOWED="skip" ;;
        esac
    fi

    for pair in "haproxy:MODE_INIT_HAPROXY" "mc-motd-fallback:MODE_INIT_MOTD"; do
        fname="${pair%%:*}"
        mvar="${pair##*:}"
        exists=0
        [ -f "$INIT_DIR/$fname" ] && exists=1
        if [ "$exists" = "1" ]; then
            printf "  ${Y}?${NC} ${INIT_DIR}/$fname exists. Overwrite? ${BOLD}[Y/n]${NC} "
            read -r input < /dev/tty || true
            case "$(printf "%s" "$input" | tr '[:upper:]' '[:lower:]')" in
                n|no) eval "${mvar}=skip" ;;
                *) ;;
            esac
        fi
    done
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
sub "${BOLD}Policy data → ${C}${HAPROXY_DIR}/${NC}"
for f in blocked_ips.txt allowed_hostnames.txt; do
    mode_var="MODE_$(printf "%s" "$f" | tr 'a-z' 'A-Z' | sed 's/\..*//')"
    eval "fmode=\${$mode_var}"
    if [ "$fmode" = "skip" ]; then
        info "$f (${Y}skipping, existing kept${NC})"
    else
        info "$f"
    fi
done

echo
sub "${BOLD}Init scripts → ${C}${INIT_DIR}/${NC}"
for pair in "haproxy:MODE_INIT_HAPROXY" "mc-motd-fallback:MODE_INIT_MOTD"; do
    fname="${pair%%:*}"
    mode_var="${pair##*:}"
    eval "fmode=\${$mode_var}"
    if [ "$fmode" = "skip" ]; then
        info "$fname (${Y}skipping${NC})"
    else
        info "$fname"
    fi
done

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

title "Installing policy data → $HAPROXY_DIR"
for f in blocked_ips.txt allowed_hostnames.txt; do
    mode_var="MODE_$(printf "%s" "$f" | tr 'a-z' 'A-Z' | sed 's/\..*//')"
    eval "fmode=\${$mode_var}"
    if [ "$fmode" = "skip" ]; then
        warn "Skipping $f (keeping existing)"
    else
        if [ "$LOCAL" = "1" ]; then
            cp "$REPO_DIR/src/examples/$f" "$HAPROXY_DIR/$f"
        else
            curl -sSfL "$BASE_URL/src/examples/$f" -o "$HAPROXY_DIR/$f"
        fi
        ok "$HAPROXY_DIR/$f"
    fi
done

title "Installing init scripts → $INIT_DIR"
mkdir -p "$INIT_DIR"
for pair in "haproxy:MODE_INIT_HAPROXY" "mc-motd-fallback:MODE_INIT_MOTD"; do
    fname="${pair%%:*}"
    mode_var="${pair##*:}"
    eval "fmode=\${$mode_var}"
    if [ "$fmode" = "skip" ]; then
        warn "Skipping $fname (keeping existing)"
    else
        if [ "$LOCAL" = "1" ]; then
            cp "$REPO_DIR/services/sysvinit/$fname" "$INIT_DIR/$fname"
        else
            curl -sSfL "$BASE_URL/services/sysvinit/$fname" -o "$INIT_DIR/$fname"
        fi
        chmod +x "$INIT_DIR/$fname"
        ok "$INIT_DIR/$fname"
    fi
done

# =============================================================================
#  Summary
# =============================================================================
echo
printf "${BOLD}${G}╔══════════════════════════════════════════════════╗${NC}\n"
printf "${BOLD}${G}║  Installation complete                           ║${NC}\n"
printf "${BOLD}${G}╚══════════════════════════════════════════════════╝${NC}\n"
echo
printf "  ${BOLD}Lua scripts:${NC}   %b\n"  "${C}${HAPROXY_DIR}/*.lua${NC}"
printf "  ${BOLD}HAProxy cfg:${NC}   %b\n"  "${C}${HAPROXY_DIR}/haproxy.cfg${NC}"
printf "  ${BOLD}Policy files:${NC}  %b\n"  "${C}${HAPROXY_DIR}/{blocked_ips,allowed_hostnames}.txt${NC}"
printf "  ${BOLD}Init scripts:${NC}  %b\n"  "${C}${INIT_DIR}/{haproxy,mc-motd-fallback}${NC}"
echo
printf "  ${BOLD}Next steps:${NC}\n"
printf "    ${Y}1.${NC} Edit ${C}${HAPROXY_DIR}/haproxy.cfg${NC} to match your backend\n"
printf "    ${Y}2.${NC} Edit ${C}${HAPROXY_DIR}/allowed_hostnames.txt${NC} with your server hostnames/domains\n"
printf "    ${Y}3.${NC} Edit ${C}${HAPROXY_DIR}/blocked_ips.txt${NC} if needed\n"
printf "    ${Y}4.${NC} Restart HAProxy: ${C}service haproxy restart${NC}\n"
echo
