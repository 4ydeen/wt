#!/bin/sh
# measure.sh - one-command local bench for the fake-SNI injection modes.
#
# Topology (all on 127.0.0.1, all local):
#
#   wattun client  --tcp-->  emulate_dpi.py  --tcp-->  wattun server
#   (metrics :19720)          (the "censor")             (metrics :19721)
#
# emulate_dpi.py applies a simulated censor rule set and models what the DPI would see for each -fake-mode
# (testbench/emulate_dpi.py --help, and the rule table in testbench/README.md). The client itself runs without
# -fake-sni here: on Windows (and for non-root Linux) wat.NewDesync fails at startup, so the fake packets cannot be
# injected for real. The emulator plays the DPI's part instead; the real injector runs only on Linux with
# CAP_NET_RAW, which is what testbench/deploy.sh does on the live pair. This is stated in results.md too.
#
# For every (mode, rule profile) pair it starts server -> emulator -> client, waits for the tunnel to come alive,
# runs the built-in /speedtest down and up through the tunnel, reads /stats, stops everything, and prints one CSV row:
#
#   mode,sni,dpi_rule,mb_per_s_down,mb_per_s_up,alive,retrans
#
# alive is the client /stats "alive" field (1 = the tunnel carries data through the emulator), retrans the
# client's packet retransmission counter when the tunnel is up (-1 when the stats endpoint was unreachable).
#
# Usage:
#   testbench/measure.sh                            # default modes and rule profiles, 4 MB speedtest
#   testbench/measure.sh -m "seq sum" -r "base throttle"
#   testbench/measure.sh -s www.example.com -n 8 > testbench/out/measured.csv
#
# Options:
#   -m LIST   modes, space separated (default: none seq ttl sum seqsum rst; split is modelled too)
#   -r LIST   rule profiles (default: base wincheck cksumcheck strict throttle; "all" = those five;
#             open = no censorship baseline, smallhello = drops hellos over 256 B)
#   -s SNI    fake SNI (default www.example.com); the allowlist is "$SNI,cdn.jsdelivr.net"
#   -n MB     speedtest size per direction for normal profiles (default 4; throttle profile uses 1)
#   -o DIR    output directory for logs (default testbench/out)
#
# Environment overrides: BIN (wattun binary), PY (python), GO, CONNS, PSK, SERVER_PORT, EMU_PORT, METRICS,
# SMETRICS, MAP_PORT, TARGET_PORT, MAX_HELLO, THROTTLE_BPS, THROTTLE_AFTER, ALIVE_WAIT.
#
# Exit status: 0 when every row ran, 1 when a row could not be measured (the row is still printed with 0 rates).
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)

MODES=${MODES:-"none seq ttl sum seqsum rst"}
PROFILES=${PROFILES:-"base wincheck cksumcheck strict throttle"}
SNI=${SNI:-www.example.com}
MB=${MB:-4}
OUT=${OUT:-$HERE/out}

PY=${PY:-}
GO=${GO:-go}
BIN=${BIN:-}
PSK=${PSK:-bench-psk}
CONNS=${CONNS:-2}
SERVER_PORT=${SERVER_PORT:-38443}
EMU_PORT=${EMU_PORT:-38444}
METRICS=${METRICS:-19720}
SMETRICS=${SMETRICS:-19721}
MAP_PORT=${MAP_PORT:-22030}
TARGET_PORT=${TARGET_PORT:-25201}
MAX_HELLO=${MAX_HELLO:-1000}
THROTTLE_BPS=${THROTTLE_BPS:-262144}
# The throttle rule fires after M seconds of a flow (emulate_dpi.py default 2 s). The bench sets M=0 for the
# throttle profile: at full local speed a 1 MB upload finishes in ~0.1 s, long before a 2 s delay would end, so the
# cap would never be observable. M only moves the start of the penalty box; the cap itself is the same.
THROTTLE_AFTER=${THROTTLE_AFTER:-0}
ALIVE_WAIT=${ALIVE_WAIT:-5}

die() { echo "measure.sh: $*" >&2; exit 1; }
say() { echo "measure.sh: $*" >&2; }

while getopts "m:r:s:n:o:h" opt; do
	case $opt in
	m) MODES=$OPTARG ;;
	r) PROFILES=$OPTARG ;;
	s) SNI=$OPTARG ;;
	n) MB=$OPTARG ;;
	o) OUT=$OPTARG ;;
	h) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	*) die "bad option (try -h)" ;;
	esac
done

[ "$PROFILES" = all ] && PROFILES="base wincheck cksumcheck strict throttle"
WHITELIST=${WHITELIST:-"$SNI,cdn.jsdelivr.net"}

# ----------------------------------------------------------------------------------------------- prerequisites

if [ -z "$PY" ]; then
	for p in python3 python; do
		if command -v "$p" >/dev/null 2>&1 && "$p" -c 'pass' >/dev/null 2>&1; then
			PY=$p
			break
		fi
	done
fi
[ -n "$PY" ] || die "no working python3/python on PATH"
command -v curl >/dev/null 2>&1 || die "curl not on PATH (needed for /stats and /speedtest)"

if [ -z "$BIN" ]; then
	case "$(uname -s)" in
	MSYS* | MINGW* | CYGWIN*) BIN=$ROOT/dist/wattun-windows-amd64.exe ;;
	*) BIN=$ROOT/dist/wattun-linux-amd64 ;;
	esac
fi
if [ ! -x "$BIN" ]; then
	say "building $BIN"
	case "$(uname -s)" in
	MSYS* | MINGW* | CYGWIN*) (cd "$ROOT" && sh build.sh windows) >&2 || die "build.sh windows failed" ;;
	*) (cd "$ROOT" && sh build.sh amd64) >&2 || die "build.sh amd64 failed" ;;
	esac
fi
[ -x "$BIN" ] || die "no executable wattun binary at $BIN"

mkdir -p "$OUT"
[ -d "$OUT" ] || die "cannot create $OUT"

# The exact bytes wat.FakeClientHello emits, dumped by the Go builder, so the emulated DPI classifies the real
# hello (including its record length). If Go is unavailable the emulator builds an equivalent one itself.
HELLO=$OUT/hello.b64
if [ -n "${FAKE_HELLO:-}" ]; then
	HELLO=$FAKE_HELLO
elif command -v "$GO" >/dev/null 2>&1; then
	if ! (cd "$ROOT" && "$GO" run ./testbench/hello_dump -sni "$WHITELIST") >"$HELLO" 2>"$OUT/hello_dump.err"; then
		rm -f "$HELLO"
		say "warning: could not dump wat.FakeClientHello with Go (see $OUT/hello_dump.err); using the emulator's own builder"
	fi
else
	say "warning: go not on PATH; using the emulator's own ClientHello builder"
fi
[ -s "$HELLO" ] || HELLO=

if [ -n "$HELLO" ]; then
	"$PY" "$HERE/emulate_dpi.py" --self-test --fake-hello "$HELLO" >"$OUT/self-test.log" 2>&1 ||
		{ cat "$OUT/self-test.log" >&2; die "emulator self-test failed"; }
else
	"$PY" "$HERE/emulate_dpi.py" --self-test >"$OUT/self-test.log" 2>&1 ||
		{ cat "$OUT/self-test.log" >&2; die "emulator self-test failed"; }
fi
say "$(cat "$OUT/self-test.log")"

# ----------------------------------------------------------------------------------------------- helpers

SPID= EPID= CPID= IPID=
STOPPED=

stop_pid() {
	pid=$1
	[ -n "$pid" ] || return 0
	kill "$pid" 2>/dev/null || true
	i=0
	while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 20 ]; do
		sleep 0.1
		i=$((i + 1))
	done
	kill -9 "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
}

stop_all() {
	stop_pid "$CPID"
	stop_pid "$EPID"
	stop_pid "$SPID"
	stop_pid "$IPID"
	CPID= EPID= SPID= IPID=
}
trap 'stop_all' EXIT INT TERM HUP

wait_http() { # wait_http URL tries(0.1s) - true when it answers 200
	i=0
	while [ "$i" -lt "$2" ]; do
		if [ "$(curl -s -o /dev/null -m 1 -w '%{http_code}' "$1" 2>/dev/null)" = 200 ]; then
			return 0
		fi
		sleep 0.1
		i=$((i + 1))
	done
	return 1
}

wait_alive() { # wait_alive - true when the client's /stats says alive
	i=0
	while [ "$i" -lt "$((ALIVE_WAIT * 2))" ]; do
		if curl -s -m 1 "http://127.0.0.1:$METRICS/stats" 2>/dev/null | grep -q '"alive":true'; then
			return 0
		fi
		sleep 0.5
		i=$((i + 1))
	done
	return 1
}

profile_flags() {
	wl="--whitelist $WHITELIST --max-hello $MAX_HELLO"
	case "$1" in
	base) echo "$wl" ;; # dumb allowlist DPI: parses the first flight, no window/checksum validation
	wincheck) echo "$wl --window-check" ;;
	cksumcheck) echo "$wl --checksum-check" ;;
	strict) echo "$wl --window-check --checksum-check --no-reassemble" ;;
	throttle) echo "$wl --throttle-bps $THROTTLE_BPS --throttle-after $THROTTLE_AFTER" ;;
	open) echo "--allow-nontls --no-whitelist" ;; # no censorship at all: the harness's own throughput
	smallhello) echo "$wl --max-hello 256" ;;     # drops every hello over 256 B, allowlist or not
	*) return 1 ;;
	esac
}

profile_mb() {
	case "$1" in
	throttle) echo 1 ;; # 1 MB at THROTTLE_BPS so the row still finishes in seconds
	*) echo "$MB" ;;
	esac
}

row_json() { # row_json STATS DOWN UP MODE PROFILE -> one CSV line
	"$PY" - "$1" "$2" "$3" "$4" "$5" "$SNI" <<'PY'
import json, sys
statf, downf, upf, mode, profile, sni = sys.argv[1:7]
def load(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}
st, dn, up = load(statf), load(downf), load(upf)
alive = 1 if st.get("alive") is True else 0
try:
    retrans = int(st.get("retrans", -1))
except (TypeError, ValueError):
    retrans = -1
down = float(dn.get("mb_per_s") or 0) if dn.get("ok") else 0.0
ups = float(up.get("mb_per_s") or 0) if up.get("ok") else 0.0
print("%s,%s,%s,%.3f,%.3f,%d,%d" % (mode, sni, profile, down, ups, alive, retrans))
PY
}

# ----------------------------------------------------------------------------------------------- one row

run_one() {
	mode=$1
	profile=$2
	# shellcheck disable=SC2046
	flags=$(profile_flags "$profile") || die "unknown rule profile '$profile' (base wincheck cksumcheck strict throttle)"
	mb=$(profile_mb "$profile")
	tag=$mode-$profile
	emu_log=$OUT/emu-$tag.log
	srv_log=$OUT/server-$tag.log
	cli_log=$OUT/client-$tag.log
	flows=$OUT/flows-$tag.jsonl
	stats_f=$OUT/stats-$tag.json
	down_f=$OUT/down-$tag.json
	up_f=$OUT/up-$tag.json
	: >"$emu_log" >"$srv_log" >"$cli_log" 2>/dev/null || true
	rm -f "$flows" "$stats_f" "$down_f" "$up_f"

	say "[$tag] starting server + emulator (rule '$profile') + client"
	# -conns 1 keeps the flow count (and the emulator log) small and the tunnel still works; speedtest uses streams
	"$BIN" -mode server -key "$PSK" -carrier tcp -listen "127.0.0.1:$SERVER_PORT" \
		-metrics "127.0.0.1:$SMETRICS" >>"$srv_log" 2>&1 &
	SPID=$!
	wait_http "http://127.0.0.1:$SMETRICS/stats" 50 || {
		stop_all
		die "server did not come up (see $srv_log)"
	}

	# shellcheck disable=SC2086
	"$PY" "$HERE/emulate_dpi.py" --listen "127.0.0.1:$EMU_PORT" --target "127.0.0.1:$SERVER_PORT" \
		--inject-fake "$mode" --fake-sni "$SNI" $flags --json-log "$flows" \
		${HELLO:+--fake-hello "$HELLO"} >>"$emu_log" 2>&1 &
	EPID=$!
	i=0
	while ! grep -q DPI_READY "$emu_log" 2>/dev/null; do
		i=$((i + 1))
		[ "$i" -lt 50 ] || {
			stop_all
			die "emulator did not start (see $emu_log)"
		}
		sleep 0.1
	done

	"$BIN" -mode client -key "$PSK" -carrier tcp -peer "127.0.0.1:$EMU_PORT" -conns "$CONNS" \
		-map "$MAP_PORT:$TARGET_PORT" -bind 127.0.0.1 -metrics "127.0.0.1:$METRICS" >>"$cli_log" 2>&1 &
	CPID=$!

	if wait_alive; then
		curl -s -m 60 "http://127.0.0.1:$METRICS/speedtest?dir=down&mb=$mb" -o "$down_f" 2>/dev/null || true
		curl -s -m 60 "http://127.0.0.1:$METRICS/speedtest?dir=up&mb=$mb" -o "$up_f" 2>/dev/null || true
		run_iperf3 "$tag"
	else
		say "[$tag] tunnel never came alive: the simulated DPI dropped every pool flow"
	fi
	: >"$stats_f" 2>/dev/null || true
	curl -s -m 2 "http://127.0.0.1:$METRICS/stats" -o "$stats_f" 2>/dev/null || true

	stop_all
	row_json "$stats_f" "$down_f" "$up_f" "$mode" "$profile"
}

# Optional iperf3 through the tunnel (target port TARGET_PORT), written to $OUT/iperf.tsv (the CSV shape is fixed,
# so iperf3 numbers do not go into it).
run_iperf3() {
	command -v iperf3 >/dev/null 2>&1 || return 0
	tag=$1
	iperf3 -s -1 -p "$TARGET_PORT" >/dev/null 2>&1 &
	IPID=$!
	sleep 0.5
	line=$(iperf3 -c 127.0.0.1 -p "$MAP_PORT" -t 2 -J 2>/dev/null |
		"$PY" -c 'import json,sys; d=json.load(sys.stdin); s=d["end"].get("sum_received") or d["end"].get("sum_sent") or {}; print("%s,up,%.3f" % ("'"$tag"'", float(s.get("bits_per_second",0))/8e6))' 2>/dev/null) || line=
	stop_pid "$IPID"
	IPID=
	if [ -n "$line" ]; then
		printf '%s,%s\n' "$tag" "$line" >>"$OUT/iperf.tsv"
	else
		say "[$tag] iperf3 present but the test failed"
	fi
}

# ----------------------------------------------------------------------------------------------- main

echo "mode,sni,dpi_rule,mb_per_s_down,mb_per_s_up,alive,retrans"
say "wattun: $("$BIN" -version 2>/dev/null || echo "$BIN") | python: $PY | hello: ${HELLO:-built-in} | out: $OUT"
say "modes: $MODES | rule profiles: $PROFILES"

for mode in $MODES; do
	for profile in $PROFILES; do
		run_one "$mode" "$profile"
	done
done

say "done; logs and JSONL flow verdicts are in $OUT"
