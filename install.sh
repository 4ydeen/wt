#!/usr/bin/env bash
# WatTunnel installer.
#   bash <(curl -fsSL https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
# Options:
#   --version vX.Y.Z   install that release instead of the latest
#   --force            reinstall even when the same version is installed
#   --uninstall        stop every tunnel and remove WatTunnel (asks before deleting /etc/wattun)
# Environment:
#   WAT_PROXY=https://ghproxy.net/   prefix for every GitHub URL (when github.com is blocked)
#   WAT_REPO=owner/name              fork to install from
# Installs: /usr/local/bin/wattun, /usr/local/bin/wattun-manager, /etc/systemd/system/wattun@.service, /etc/wattun/
set -euo pipefail

REPO=${WAT_REPO:-JohnWatsoon/WatTunnel}
PROXY=${WAT_PROXY:-}
BIN=/usr/local/bin/wattun
MGR=/usr/local/bin/wattun-manager
UNIT=/etc/systemd/system/wattun@.service
CONF=/etc/wattun
VERSION=latest
FORCE=0
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo /nonexistent)

ART=(
  ' ▄▄▄  ▄▄▄  ▄▄▄                                    | ▄▄▄▄▄▄▄ ▄▄▄ ▄▄▄  ▄▄▄  ▄▄'
  ' ███  ███  ███        ███                         | ▀▀███▀▀ ███ ███  ███  ██'
  '  ██▄ ███ ███ ▄█████▄ ████ ▄█████▄ ▄█████▄ ███▄██▄|   ███   ███ ███  ████ ██'
  '  ███ █ █ ███ ███ ███ ███  ███ ▀▀▀ ███ ███ ███ ███|   ███   ███ ███  ████▄██'
  '  ███ █ █ ███ ▄▄█████ ███   ▀███▄▄ ███ ███ ███ ███|   ███   ███ ███  ██ ████'
  '   ██▄█ █▄██  ███ ███ ███  ▄▄▄ ███ ███ ███ ███ ███|   ███   ███ ███  ██ ▀███'
  '   ███   ███  ▀██▀███ ████ ▀█████▀ ▀█████▀ ███ ███|   ███   ▀▀████▀  ██  ███'
)
banner() {
  [ -t 1 ] && printf '\033[H\033[2J\033[3J'
  local l; echo
  for l in "${ART[@]}"; do printf '\033[1;36m%s\033[1;33m%s\033[0m\n' "${l%%|*}" "${l#*|}"; done
}
page() { # title [subtitle]
  banner
  printf '\033[90m  %s\033[0m\n' "─────────────────────────────────────────────────────────────────────────"
  printf '  \033[1;37m%s\033[0m%s\n\n' "$1" "${2:+   $(printf '\033[90m%s\033[0m' "$2")}"
}

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
die()   { red "ERROR: $*"; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION=${2:?}; shift 2 ;;
    --force) FORCE=1; shift ;;
    --uninstall) MODE=uninstall; shift ;;
    -h|--help) sed -n 2,11p "$0"; exit 0 ;;
    *) die "unknown option $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root"
command -v systemctl >/dev/null || die "systemd is required"

uninstall() {
  for u in $(systemctl list-units --all --plain --no-legend 'wattun@*' | awk '{print $1}'); do
    systemctl disable --now "$u" >/dev/null 2>&1 || true
  done
  rm -f "$UNIT" "$BIN" "$BIN.prev" "$MGR"
  systemctl daemon-reload
  if [ -d "$CONF" ]; then
    read -rp "Delete $CONF (tunnel configs and keys)? [y/N] " a
    [[ "$a" =~ ^[Yy]$ ]] && rm -rf "$CONF"
  fi
  green "WatTunnel removed."
}
[ "${MODE:-}" = uninstall ] && { page "Uninstall"; uninstall; exit 0; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported CPU $(uname -m) (amd64 and arm64 only)" ;;
esac

fetch() { # url dest
  if command -v curl >/dev/null; then curl -fsSL --retry 3 --connect-timeout 15 -o "$2" "$PROXY$1"
  else wget -q -T 15 -t 3 -O "$2" "$PROXY$1"; fi
}

page "Installer" "WatTunnel for linux/$ARCH"
echo "  This will install:"
echo "    /usr/local/bin/wattun           the tunnel"
echo "    /usr/local/bin/wattun-manager   the menu to set up and manage tunnels"
echo "    wattun@.service                 systemd template, one unit per tunnel"
echo
if [ -t 0 ]; then read -rp "  Press Enter to start, or Ctrl+C to cancel " _; page "Installing" "WatTunnel for linux/$ARCH"; fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
NAME=wattun-linux-$ARCH

# 1. The binary: a local build in a cloned repo, else the GitHub release, else build from source.
if [ -f "$HERE/dist/$NAME" ]; then
  echo "Using local $HERE/dist/$NAME"
  cp "$HERE/dist/$NAME" "$TMP/wattun"
  [ -f "$HERE/dist/$NAME.sha256" ] && cp "$HERE/dist/$NAME.sha256" "$TMP/sum"
else
  if [ "$VERSION" = latest ]; then base="https://github.com/$REPO/releases/latest/download"
  else base="https://github.com/$REPO/releases/download/$VERSION"; fi
  echo "Downloading $NAME ($VERSION)..."
  if fetch "$base/$NAME" "$TMP/wattun"; then
    fetch "$base/$NAME.sha256" "$TMP/sum" || die "could not download the checksum"
  elif [ -f "$HERE/go.mod" ] && command -v go >/dev/null; then
    echo "Download failed, building from source..."
    (cd "$HERE" && sh build.sh "$ARCH") || die "build failed"
    cp "$HERE/dist/$NAME" "$TMP/wattun"; cp "$HERE/dist/$NAME.sha256" "$TMP/sum"
  else
    die "download failed. If GitHub is blocked, try: WAT_PROXY=https://ghproxy.net/ bash install.sh"
  fi
fi
if [ -f "$TMP/sum" ]; then
  want=$(awk '{print $1}' "$TMP/sum")
  got=$(sha256sum "$TMP/wattun" | awk '{print $1}')
  [ "$want" = "$got" ] || die "checksum mismatch (want $want, got $got)"
fi
chmod 755 "$TMP/wattun"
NEW=$("$TMP/wattun" -version 2>&1 | awk '{print $2}') || true
[ -n "$NEW" ] || die "the downloaded binary does not run on this system"

OLD=""
[ -x "$BIN" ] && OLD=$("$BIN" -version 2>/dev/null | awk '{print $2}') || true
if [ "$OLD" = "$NEW" ] && [ "$FORCE" = 0 ]; then
  echo "wattun $NEW is already installed (use --force to reinstall)."
else
  [ -x "$BIN" ] && cp -f "$BIN" "$BIN.prev"
  install -m 755 "$TMP/wattun" "$BIN.new" && mv -f "$BIN.new" "$BIN"
  green "Installed wattun $NEW${OLD:+ (was $OLD)}"
fi

# 2. The manager.
if [ -f "$HERE/wattun-manager" ]; then cp "$HERE/wattun-manager" "$TMP/mgr"
else fetch "https://raw.githubusercontent.com/$REPO/main/wattun-manager" "$TMP/mgr" || die "could not download wattun-manager"; fi
# atomic replace: a manager that is running right now keeps reading its old file safely
install -m 755 "$TMP/mgr" "$MGR.new" && mv -f "$MGR.new" "$MGR"

# 3. The systemd template: wattun@NAME reads /etc/wattun/NAME.yml.
mkdir -p "$CONF"; chmod 700 "$CONF"
cat > "$TMP/unit" <<'EOF'
[Unit]
Description=WatTunnel %i
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/wattun -config /etc/wattun/%i.yml
Restart=always
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
if ! cmp -s "$TMP/unit" "$UNIT" 2>/dev/null; then install -m 644 "$TMP/unit" "$UNIT"; fi
systemctl daemon-reload

running=$(systemctl list-units --state=active --plain --no-legend 'wattun@*' | awk '{print $1}' | xargs)
if [ -n "$running" ] && [ -n "$OLD" ] && [ "$OLD" != "$NEW" ]; then
  echo "Running tunnels still use the old version: $running"
  echo "Restart them from wattun-manager when convenient (a restart drops open connections)."
fi
if [ -t 0 ] && [ -z "$running" ]; then
  page "Installed" "wattun $NEW"
  echo "Which side is this server?"
  echo "  1) Kharej - outside server, where your service runs (set this up first)"
  echo "  2) Iran   - inside server that users connect to (needs the token from Kharej)"
  echo "  3) Later"
  read -rp "Choice [3]: " side
  case "$side" in 1) exec "$MGR" kharej ;; 2) exec "$MGR" iran ;; esac
fi
green "Done. Manage tunnels any time with: wattun-manager"
