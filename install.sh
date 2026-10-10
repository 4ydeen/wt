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
#   WAT_NO_ANIM=1                    no animations (also automatic when output is not a terminal)
#   NO_COLOR=1                       no colours
# Installs: /usr/local/bin/wattun, /usr/local/bin/wattun-manager, /etc/systemd/system/wattun@.service, /etc/wattun/
set -uo pipefail
shopt -s extglob

REPO=${WAT_REPO:-JohnWatsoon/WatTunnel}
PROXY=${WAT_PROXY:-}
BIN=${WAT_BIN:-/usr/local/bin/wattun}
MGR=${WAT_MGR:-/usr/local/bin/wattun-manager}
UNIT=${WAT_UNIT:-/etc/systemd/system/wattun@.service}
CONF=${WAT_CONF:-/etc/wattun}
VERSION=latest
FORCE=0
MODE=install
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo /nonexistent)
# Local files (dist/ build, wattun-manager) are used only when this script sits in a real checkout or unpacked
# release. The manager's update runs a downloaded copy from a temp dir: there a stale /tmp/dist/ must not be
# picked up and "installed" again, so it always downloads.
if [ "${WAT_FROM_MANAGER:-0}" = 1 ] || [ ! -f "$HERE/install.sh" ]; then HERE=/nonexistent; fi

case "$(locale charmap 2>/dev/null)" in UTF-8) ;; *) export LC_ALL=C.UTF-8 ;; esac

# ======================================================================================
#  Terminal UI: colours, gradient banner, spinner, step checklist
# ======================================================================================
IS_TTY=0; [ -t 1 ] && IS_TTY=1
USE_COLOR=0
if [ "${WAT_FORCE_COLOR:-0}" = 1 ] || { [ "$IS_TTY" = 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; }; then USE_COLOR=1; fi
NCOL=8
if [ "$USE_COLOR" = 1 ]; then
  NCOL=$(tput colors 2>/dev/null || echo 8)
  case "${TERM:-}" in *256color*) NCOL=256 ;; esac
  case "$NCOL" in ''|*[!0-9]*) NCOL=8 ;; esac
  RST=$'\e[0m'; BOLD=$'\e[1m'; RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYN=$'\e[36m'; GRY=$'\e[90m'
else
  RST=''; BOLD=''; RED=''; GRN=''; YEL=''; CYN=''; GRY=''
fi
ANIM=0
if [ "$IS_TTY" = 1 ] && [ "${WAT_NO_ANIM:-0}" != 1 ]; then ANIM=1; fi

SPIN_PID=''
TMP=''
cur_hide() { [ "$IS_TTY" = 1 ] && printf '\e[?25l'; return 0; }
cur_show() { [ "$IS_TTY" = 1 ] && printf '\e[?25h'; return 0; }
kill_spin() {
  if [ -n "$SPIN_PID" ]; then kill "$SPIN_PID" 2>/dev/null; wait "$SPIN_PID" 2>/dev/null; SPIN_PID=''; fi
  return 0
}
cleanup() { kill_spin; cur_show; [ -n "$TMP" ] && rm -rf "$TMP"; return 0; }
trap cleanup EXIT
trap 'cleanup; printf "\n"; exit 130' INT
trap 'cleanup; exit 143' TERM HUP

rep() { local s; printf -v s '%*s' "$2" ''; printf '%s' "${s// /$1}"; }
vlen() { local s=${1//$'\e'\[*([0-9;?])[a-zA-Z]/}; VLEN=${#s}; }
VLEN=0
ok()   { printf '  %s✔%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '  %s!%s %s\n' "$YEL" "$RST" "$*"; }
err()  { printf '  %s✘%s %s\n' "$RED" "$RST" "$*"; }
hint() { printf '  %s%s%s\n' "$GRY" "$*" "$RST"; }
die()  { cur_show; err "$*"; exit 1; }
hr()   { printf '  %s%s%s\n' "$GRY" "$(rep ─ 74)" "$RST"; }

GR_N=(51 45 39 33 63 99 135 171)
GR_F=(36 36 36 34 34 35 35 35)
GFG=''
gfg() {
  GFG=''; [ "$USE_COLOR" = 1 ] || return 0
  local i=$(( $1 % 8 ))
  if [ "$NCOL" -ge 256 ]; then printf -v GFG '\e[1;38;5;%sm' "${GR_N[$i]}"; else printf -v GFG '\e[1;%sm' "${GR_F[$i]}"; fi
}
KITE=(
  '       .'
  '      /|\'
  '     / | \'
  '    <--+-->'
  '     \ | /'
  '      \|/'
  '       `.'
  '         `-.'
)
mapfile -t TXT <<'EOF'
__        __    _  _____                       _
\ \      / /_ _| ||_   _|   _ _ __  _ __   ___| |
 \ \ /\ / / _` | __|| || | | | '_ \| '_ \ / _ \ |
  \ V  V / (_| | |_ | || |_| | | | | | | |  __/ |
   \_/\_/ \__,_|\__||_| \__,_|_| |_|_| |_|\___|_|
EOF
TAGLINE='encrypted port forwarding, even when only ping works'
B_K=(); B_T=()
for i in 0 1 2 3 4 5 6 7; do
  printf -v k '%-17s' "${KITE[$i]}"; B_K[i]=$k
  if [ "$i" -ge 2 ] && [ "$i" -le 6 ]; then B_T[i]=${TXT[$((i-2))]}; elif [ "$i" -eq 7 ]; then B_T[i]=$TAGLINE; else B_T[i]=''; fi
done
banner() { # [1 = animated line-by-line reveal]
  local i kc
  for i in 0 1 2 3 4 5 6 7; do
    kc=''
    if [ "$USE_COLOR" = 1 ]; then
      if [ "$NCOL" -ge 256 ]; then [ "$i" -le 5 ] && kc=$'\e[1;38;5;221m' || kc=$'\e[1;38;5;213m'
      else [ "$i" -le 5 ] && kc=$'\e[1;33m' || kc=$'\e[1;35m'; fi
    fi
    gfg "$i"; [ "$i" -eq 7 ] && GFG=$GRY
    printf '  %s%s%s%s%s%s\n' "$kc" "${B_K[$i]}" "$RST" "$GFG" "${B_T[$i]}" "$RST"
    [ "${1:-0}" = 1 ] && sleep 0.035
  done
  return 0
}
page() { # title [subtitle]
  [ "$IS_TTY" = 1 ] && printf '\e[H\e[2J\e[3J'
  echo
  if [ "$ANIM" = 1 ]; then banner 1; else banner 0; fi
  hr
  printf '  %s%s%s%s\n\n' "$BOLD" "$1" "$RST" "${2:+   ${GRY}$2${RST}}"
}
step_diagram() {
  local top; top=$(rep ─ 27)
  printf '  %s┌%s┐%s          %s┌%s┐%s\n' "$BOLD$CYN" "$top" "$RST" "$BOLD" "$top" "$RST"
  printf '  %s│ %-25s │%s %s─token─►%s %s│ %-25s │%s\n' "$BOLD$CYN" "STEP 1  Kharej (outside)" "$RST" "$GRY" "$RST" "$BOLD" "STEP 2  Iran (inside)" "$RST"
  printf '  %s│ %-25s │%s          %s│ %-25s │%s\n' "$BOLD$CYN" "do this one FIRST" "$RST" "$BOLD" "paste the token here" "$RST"
  printf '  %s└%s┘%s          %s└%s┘%s\n' "$BOLD$CYN" "$top" "$RST" "$BOLD" "$top" "$RST"
}

# ---- step checklist: ◌ pending -> spinner -> ✔ done / ✘ failed (rows are rewritten in place) ----
SPIN_FR=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
CL_LABELS=(); CL_N=0; DETAIL=''; ERRMSG=''
cl_row() { # idx text : rewrite checklist row idx in place
  local up=$((CL_N - $1))
  printf '\e[%dA\r\e[K%s\e[%dB\r' "$up" "$2" "$up"
}
cl_init() {
  local l; CL_LABELS=("$@"); CL_N=$#
  [ "$ANIM" = 1 ] || return 0
  for l in "$@"; do printf '  %s◌ %s%s\n' "$GRY" "$l" "$RST"; done
}
cl_start() { # idx
  [ "$ANIM" = 1 ] || return 0
  local idx=$1 label=${CL_LABELS[$1]}
  cur_hide
  (
    local i=0 t0=$SECONDS up=$((CL_N - idx))
    while :; do
      printf '\e[%dA\r\e[K  %s%s%s %s %s(%ds)%s\e[%dB\r' "$up" "$CYN" "${SPIN_FR[$i]}" "$RST" "$label" "$GRY" $((SECONDS-t0)) "$RST" "$up"
      i=$(( (i+1) % 10 )); sleep 0.1
    done
  ) &
  SPIN_PID=$!
}
cl_end() { # idx rc
  local idx=$1 rc=$2 label=${CL_LABELS[$1]} line
  kill_spin
  if [ "$rc" -eq 0 ]; then line=$(printf '  %s✔%s %s%s%s' "$GRN" "$RST" "$label" "${DETAIL:+   $GRY$DETAIL$RST}" "")
  elif [ "$rc" -eq 2 ]; then line=$(printf '  %s–%s %s%s' "$GRY" "$RST" "$label" "${DETAIL:+   $GRY$DETAIL$RST}")
  else line=$(printf '  %s✘%s %s' "$RED" "$RST" "$label"); fi
  if [ "$ANIM" = 1 ]; then cl_row "$idx" "$line"; cur_show; else printf '%s\n' "$line"; fi
}
run_step() { # idx fn : rc 0 ok, 2 skipped (fn returns 2), else failure -> abort with ERRMSG
  local idx=$1 rc; DETAIL=''; ERRMSG=''
  cl_start "$idx"
  "$2"; rc=$?
  cl_end "$idx" "$rc"
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then echo; die "${ERRMSG:-step failed}"; fi
  return 0
}
box() { # title lines... (plain or coloured)
  local w=66 t=$1 l pad; shift
  printf '  %s┌─ %s%s%s%s %s┐%s\n' "$GRY" "$RST" "$BOLD$t" "$RST" "$GRY" "$(rep ─ $((w-${#t}-3)))" "$RST"
  for l in "$@"; do vlen "$l"; pad=$((w-2-VLEN)); [ "$pad" -lt 0 ] && pad=0; printf '  %s│%s %s%*s %s│%s\n' "$GRY" "$RST" "$l" "$pad" '' "$GRY" "$RST"; done
  printf '  %s└%s┘%s\n' "$GRY" "$(rep ─ "$w")" "$RST"
}
usage() {
  cat <<'EOF'
WatTunnel installer
  --version vX.Y.Z   install that release instead of the latest
  --force            reinstall even when the same version is installed
  --uninstall        stop every tunnel and remove WatTunnel (asks before deleting /etc/wattun)
Environment: WAT_PROXY=https://ghproxy.net/  WAT_REPO=owner/name  WAT_NO_ANIM=1  NO_COLOR=1
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version) [ $# -ge 2 ] || die "--version needs a value (example: --version v1.9.0)"; VERSION=$2; shift 2 ;;
    --force) FORCE=1; shift ;;
    --uninstall) MODE=uninstall; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option $1 (see --help)" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "run as root (sudo bash install.sh)"
command -v systemctl >/dev/null || die "systemd is required"

tunnel_list() { local f b; for f in "$CONF"/*.yml; do [ -e "$f" ] || continue; b=${f##*/}; echo "${b%.yml}"; done; }

# ======================================================================================
#  Uninstall
# ======================================================================================
uninstall() {
  local list=() n u a
  while IFS= read -r n; do [ -n "$n" ] && list+=("$n"); done < <(tunnel_list)
  page "Uninstall" "remove WatTunnel from this server"
  if [ "${#list[@]}" -gt 0 ]; then
    echo "  These tunnels will be stopped and disabled:"; echo
    for n in "${list[@]}"; do
      u=stopped; systemctl is-active -q "wattun@$n" 2>/dev/null && u=running
      printf '      %s%-16s%s %s\n' "$BOLD" "$n" "$RST" "$u"
    done
    echo
  else hint "No tunnels are configured."; echo; fi
  if [ "${WAT_YES:-0}" != 1 ] && [ -t 0 ]; then
    printf '  %s?%s Remove WatTunnel? %s[y/N]%s ' "$CYN" "$RST" "$GRY" "$RST"
    IFS= read -rsn1 a || a=n; echo
    case "$a" in y|Y) ;; *) warn "Cancelled. Nothing was changed."; exit 0 ;; esac
  fi
  for u in $(systemctl list-units --all --plain --no-legend 'wattun@*' 2>/dev/null | awk '{print $1}'); do
    systemctl disable --now "$u" >/dev/null 2>&1
  done
  systemctl disable --now wattun-heal.timer >/dev/null 2>&1
  rm -f "$UNIT" "$BIN" "$BIN.prev" "$MGR" /etc/systemd/system/wattun-heal.service /etc/systemd/system/wattun-heal.timer
  systemctl daemon-reload
  ok "Services, binary and manager removed"
  if [ -d "$CONF" ]; then
    if [ "${WAT_PURGE:-}" = 1 ]; then a=y
    elif [ -t 0 ]; then printf '  %s?%s Also delete %s (tunnel configs, keys, tokens)? %s[y/N]%s ' "$CYN" "$RST" "$CONF" "$GRY" "$RST"; IFS= read -rsn1 a || a=n; echo
    else a=n; fi
    case "$a" in y|Y) rm -rf "$CONF"; ok "Configuration deleted" ;; *) hint "Kept $CONF (delete it by hand if you do not need it)." ;; esac
  fi
  echo; ok "WatTunnel removed."
}
if [ "$MODE" = uninstall ]; then uninstall; exit 0; fi

# ======================================================================================
#  Install steps (each one is silent; the checklist shows the result)
# ======================================================================================
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported CPU $(uname -m) (amd64 and arm64 only)" ;;
esac
NAME=wattun-linux-$ARCH
NEW=''; OLD=''

fetch() { # url dest
  if command -v curl >/dev/null; then curl -fsSL --retry 3 --connect-timeout 15 --max-time 300 -o "$2" "$PROXY$1"
  elif command -v wget >/dev/null; then wget -q -T 20 -t 3 -O "$2" "$PROXY$1"
  else return 127; fi
}
# resolve_tag: the tag that releases/latest points to, so the binary and the manager come from the SAME release
# (the manager used to come from main while the binary came from the latest release, and the two could disagree).
resolve_tag() {
  local u
  [ "$VERSION" = latest ] || { TAG=$VERSION; return 0; }
  command -v curl >/dev/null || return 1
  u=$(curl -fsSLI -o /dev/null -w '%{url_effective}' --connect-timeout 15 --max-time 30 "${PROXY}https://github.com/$REPO/releases/latest" 2>/dev/null) || return 1
  u=${u%/}; u=${u##*/}
  [[ "$u" =~ ^v[0-9]+\.[0-9]+ ]] || return 1
  TAG=$u
}
TAG=''
human_size() { awk -v b="$1" 'BEGIN{printf "%.1f MB", b/1048576}'; }

step_check() {
  command -v curl >/dev/null || command -v wget >/dev/null || [ -f "$HERE/dist/$NAME" ] || { ERRMSG="curl or wget is required to download WatTunnel"; return 1; }
  mkdir -p "$TMP" || { ERRMSG="cannot create a temporary directory"; return 1; }
  DETAIL="linux/$ARCH, systemd $(systemctl --version 2>/dev/null | awk 'NR==1{print $2}')"
}
step_get() {
  local base
  if [ -f "$HERE/dist/$NAME" ]; then
    cp "$HERE/dist/$NAME" "$TMP/wattun" || { ERRMSG="cannot read $HERE/dist/$NAME"; return 1; }
    [ -f "$HERE/dist/$NAME.sha256" ] && cp "$HERE/dist/$NAME.sha256" "$TMP/sum"
    DETAIL="local build (dist/)"; return 0
  fi
  resolve_tag || TAG=''
  if [ -n "$TAG" ]; then base="https://github.com/$REPO/releases/download/$TAG"
  else base="https://github.com/$REPO/releases/latest/download"; fi
  if fetch "$base/$NAME" "$TMP/wattun"; then
    fetch "$base/$NAME.sha256" "$TMP/sum" || { ERRMSG="could not download the checksum file"; return 1; }
    DETAIL="release ${TAG:-latest}, $(human_size "$(stat -c %s "$TMP/wattun")")"
  elif [ -f "$HERE/go.mod" ] && command -v go >/dev/null; then
    (cd "$HERE" && timeout 900 sh build.sh "$ARCH") >"$TMP/build.log" 2>&1 || { ERRMSG="download failed and the source build failed too (see: sh build.sh)"; return 1; }
    cp "$HERE/dist/$NAME" "$TMP/wattun"; cp "$HERE/dist/$NAME.sha256" "$TMP/sum"
    DETAIL="built from source"
  else
    ERRMSG="download failed. If GitHub is blocked, try: WAT_PROXY=https://ghproxy.net/ bash install.sh"; return 1
  fi
}
step_verify() {
  local want got
  if [ -f "$TMP/sum" ]; then
    want=$(awk '{print $1}' "$TMP/sum"); got=$(sha256sum "$TMP/wattun" | awk '{print $1}')
    [ "$want" = "$got" ] || { ERRMSG="checksum mismatch (want $want, got $got)"; return 1; }
    DETAIL="sha256 ${got:0:12}... ok"
  else DETAIL="no checksum file, skipped"; fi
  chmod 755 "$TMP/wattun"
  NEW=$("$TMP/wattun" -version 2>&1 | awk '{print $2; exit}')
  [ -n "$NEW" ] || { ERRMSG="the downloaded binary does not run on this system"; return 1; }
}
step_install_bin() {
  [ -x "$BIN" ] && OLD=$("$BIN" -version 2>/dev/null | awk '{print $2; exit}')
  if [ "$OLD" = "$NEW" ] && [ "$FORCE" = 0 ]; then DETAIL="$NEW already installed (--force reinstalls)"; return 2; fi
  [ -x "$BIN" ] && cp -f "$BIN" "$BIN.prev"
  install -m 755 "$TMP/wattun" "$BIN.new" && mv -f "$BIN.new" "$BIN" || { ERRMSG="cannot write $BIN"; return 1; }
  # prove it: the file on disk must now report the new version
  local now; now=$("$BIN" -version 2>/dev/null | awk '{print $2; exit}')
  [ "$now" = "$NEW" ] || { ERRMSG="$BIN still reports ${now:-nothing} after installing $NEW"; return 1; }
  DETAIL="$NEW${OLD:+ (was $OLD)}"
}
step_install_mgr() {
  if [ -f "$HERE/wattun-manager" ]; then cp "$HERE/wattun-manager" "$TMP/mgr"
  elif [ -n "$TAG" ] && fetch "https://raw.githubusercontent.com/$REPO/$TAG/wattun-manager" "$TMP/mgr"; then :
  else fetch "https://raw.githubusercontent.com/$REPO/main/wattun-manager" "$TMP/mgr" || { ERRMSG="could not download wattun-manager"; return 1; }; fi
  head -c 2 "$TMP/mgr" | grep -q '#!' || { ERRMSG="wattun-manager looks corrupt"; return 1; }
  # atomic replace: a manager that is running right now keeps reading its old file safely
  install -m 755 "$TMP/mgr" "$MGR.new" && mv -f "$MGR.new" "$MGR" || { ERRMSG="cannot write $MGR"; return 1; }
  DETAIL="${MGR##*/} command${TAG:+ ($TAG)}"
}
step_systemd() {
  mkdir -p "$CONF" && chmod 700 "$CONF"
  cat >"$TMP/unit" <<'EOF'
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
  if ! cmp -s "$TMP/unit" "$UNIT" 2>/dev/null; then install -m 644 "$TMP/unit" "$UNIT" || { ERRMSG="cannot write $UNIT"; return 1; }; fi
  systemctl daemon-reload || { ERRMSG="systemctl daemon-reload failed"; return 1; }
  DETAIL="wattun@.service (one unit per tunnel)"
}

# ======================================================================================
#  Main
# ======================================================================================
TMP=$(mktemp -d)
page "Installer" "WatTunnel for linux/$ARCH"
cl_init "Check system" "Get wattun (${VERSION/latest/latest release})" "Verify checksum and binary" "Install wattun" "Install wattun-manager" "Set up systemd"
run_step 0 step_check
run_step 1 step_get
run_step 2 step_verify
run_step 3 step_install_bin
run_step 4 step_install_mgr
run_step 5 step_systemd
echo

# ---- summary ----
total=0; running=0; stale_names=''
# A running tunnel keeps executing the binary it started with; after the file is replaced /proc/PID/exe reads
# "... (deleted)". Those tunnels still run the OLD version until they are restarted.
is_stale() { local pid; pid=$(systemctl show -p MainPID --value "wattun@$1" 2>/dev/null); [ -n "$pid" ] && [ "$pid" != 0 ] && [[ "$(readlink "/proc/$pid/exe" 2>/dev/null)" == *"(deleted)"* ]]; }
while IFS= read -r n; do
  [ -n "$n" ] || continue
  total=$((total+1))
  if systemctl is-active -q "wattun@$n" 2>/dev/null; then running=$((running+1)); is_stale "$n" && stale_names="$stale_names $n"; fi
done < <(tunnel_list)
prev=''; [ -x "$BIN.prev" ] && prev=$("$BIN.prev" -version 2>/dev/null | awk '{print $2; exit}')
if [ -n "$OLD" ] && [ "$OLD" = "$NEW" ] && [ "$FORCE" = 0 ]; then title="Already up to date: WatTunnel $NEW"
elif [ -n "$OLD" ]; then title="Updated WatTunnel $OLD -> $NEW"
else title="WatTunnel $NEW is installed"; fi
box "$title" \
  "${BOLD}wattun${RST}          $BIN" \
  "${BOLD}manager${RST}         $MGR" \
  "${BOLD}tunnels${RST}         $total configured, $running running" \
  "${BOLD}previous${RST}        ${prev:-none}${prev:+   (roll back from the manager)}"
if [ -n "$stale_names" ]; then
  echo
  warn "These tunnels are still running the OLD binary:${stale_names}"
  hint "They switch to $NEW only after a restart (wattun-manager -> Settings -> restart all; open connections drop)."
fi
echo

# ---- what next ----
if [ "${WAT_FROM_MANAGER:-0}" = 1 ]; then exit 0; fi
if [ -t 0 ] && [ -t 1 ]; then
  if [ "$total" -eq 0 ]; then
    echo "  ${BOLD}Next: set up the tunnel. You need two servers, in this order:${RST}"
    echo
    step_diagram
    echo
    echo "  Which side is THIS server?"
    echo "    ${CYN}1${RST}  ${BOLD}Kharej${RST}  outside server, where your service runs   ${YEL}<- do this FIRST${RST}"
    echo "    ${CYN}2${RST}  ${BOLD}Iran${RST}    inside server, I already have the token"
    echo "    ${CYN}3${RST}  Later (run ${BOLD}wattun-manager${RST} any time)"
    echo
    for t in 1 2 3; do
      printf '  %s?%s Press 1, 2 or 3 %s[3]%s ' "$CYN" "$RST" "$GRY" "$RST"
      IFS= read -rsn1 side || { echo; side=3; }
      echo "$side"
      case "$side" in
        1) cleanup; exec "$MGR" kharej ;;
        2) cleanup; exec "$MGR" iran ;;
        3|'') break ;;
        *) warn "Press 1, 2 or 3." ;;
      esac
    done
  else
    printf '  %s?%s Open the manager now? %s[Y/n]%s ' "$CYN" "$RST" "$GRY" "$RST"
    IFS= read -rsn1 a || a=n
    echo
    case "$a" in n|N) ;; *) cleanup; exec "$MGR" ;; esac
  fi
fi
echo "  Done. Manage tunnels any time with: ${BOLD}wattun-manager${RST}"
if [ "$total" -eq 0 ]; then hint "Remember the order: Kharej first (it makes the token), then Iran."; fi
