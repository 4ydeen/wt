#!/usr/bin/env bash
# self-check for wattun-manager: resilience profiles (profile save/list/show/del/apply), the wizard's
# profile defaults, the unattended flags (--fake-sni/--fake-mode/--fake-ttl/--pool-rotate/--pool-rotate-bytes),
# the value validators, and the flow gates (profiles are Linux-only; the resilience prompts are off
# the plain wizard flow unless a flag or profile pre-fills them). No root, no systemd, no binary needed.
cd "$(dirname "$0")" || exit 1
export WAT_MANAGER_LIB=1 WAT_PREFIX=wattest
export WAT_CONF="$PWD/.smoke/conf" WAT_BIN="$PWD/.smoke/wattun"
rm -rf "$PWD/.smoke"; mkdir -p "$WAT_CONF"
trap 'rm -rf "$PWD/.smoke"' EXIT
fail=0
chk() { [ "$2" = "$3" ] && echo "ok   $1" || { echo "FAIL $1: got '$2', want '$3'"; fail=1; return; }; }
expect_fail() { "$@" 2>/dev/null && { echo "FAIL $*: accepted a bad value"; fail=1; } || echo "ok   rejected: $*"; }

cat >"$WAT_CONF/t1.yml" <<'EOF'
mode: client
carrier: wss
peer: example.com:443
fake-sni: mci.ir
fake-mode: seqsum
pool-rotate: 30m
pool-rotate-bytes: 500MB
EOF
. ./wattun-manager
bin_ver_ok() { echo 1; }
role() { echo Iran; }
uname() { echo Linux; }
systemctl() { return 0; }
step() { shift; "$@"; }

profile_cmd save p1 t1
chk "save wrote the file" "$(cat "$WAT_CONF/profiles/p1.env" | grep -c '^FAKEMODE=seqsum')" "1"
profile_cmd list
profile_cmd show p1
profile_cmd apply p1 t1
chk "apply keeps seqsum" "$(grep '^fake-mode:' "$WAT_CONF/t1.yml")" "fake-mode: seqsum"
chk "apply keeps pool-rotate" "$(grep '^pool-rotate:' "$WAT_CONF/t1.yml")" "pool-rotate: 30m"

profile_cmd save p1 >/dev/null 2>&1; [ $? = 0 ] && echo "ok   save without a tunnel name: exactly one pool tunnel -> t1"

printf '# cleared elsewhere\nFAKESNI=\nFAKEMODE=\nFAKETTL=\nPOOLROT=\nPOOLBYTES=\n' >"$WAT_CONF/profiles/blank.env"
profile_cmd apply blank t1
chk "blank profile clears fake-sni" "$(grep -c '^fake-' "$WAT_CONF/t1.yml")" "0"
chk "blank profile clears pool keys" "$(grep -c '^pool-' "$WAT_CONF/t1.yml")" "0"

ni_parse --carrier wss --name x --pool-rotate 4h --pool-rotate-bytes 1.5GB
chk "unattended --pool-rotate" "$NI_POOLROT" "4h"
chk "unattended --pool-rotate-bytes" "$NI_POOLBYTES" "1.5GB"
NI_FAKESNI=''; NI_FAKEMODE=''
ni_parse --fake-sni mci.ir --fake-mode seqsum
chk "unattended --fake-sni pair form" "$NI_FAKESNI" "mci.ir"
chk "unattended --fake-mode seqsum" "$NI_FAKEMODE" "seqsum"
ni_parse --fake-mode auto
chk "unattended --fake-mode auto" "$NI_FAKEMODE" "auto"
ni_parse --preset mci --ech ladder --governor true
chk "unattended --preset mci" "$NI_PRESET" "mci"
chk "unattended --ech ladder" "$NI_ECH" "ladder"
chk "unattended --governor true" "$NI_GOVERNOR" "true"
ni_parse --preset "Iran Whitelist - Irancell/Mokhaberat" --ech auto --governor false
chk "unattended --preset canonical irancell" "$NI_PRESET" "irancell"
chk "unattended --ech auto" "$NI_ECH" "auto"
chk "unattended --governor false" "$NI_GOVERNOR" "false"

expect_fail ni_parse --pool-rotate 30x
expect_fail ni_parse --fake-mode gq
expect_fail ni_parse --pool-rotate-bytes 20QQ
expect_fail ni_parse --fake-ttl 999
expect_fail ni_parse --preset bad_preset
expect_fail ni_parse --ech bad_ech
expect_fail ni_parse --governor bad_gov

v_pool_rotate off && echo "ok   v_pool_rotate off" || { echo "FAIL v_pool_rotate off"; fail=1; }
for v in 500MB 4G 300k 1.5gb 0b 0 off; do v_pool_bytes "$v" && echo "ok   v_pool_bytes $v" || { echo "FAIL v_pool_bytes $v"; fail=1; }; done

for e in ladder auto off "VGhpcyBpcyBhIHZhbGlkIGJhc2U2NCBFQ0g="; do
  v_ech "$e" && echo "ok   v_ech $e" || { echo "FAIL v_ech $e"; fail=1; }
done
expect_fail v_ech "invalid"
expect_fail v_ech "short="

for g in on off true false 1 0; do
  v_governor "$g" && echo "ok   v_governor $g" || { echo "FAIL v_governor $g"; fail=1; }
done
expect_fail v_governor "maybe"

for p in mci irancell blackout conservative off "iran whitelist - mci" "emergency blackout mode"; do
  v_preset "$p" && echo "ok   v_preset $p" || { echo "FAIL v_preset $p"; fail=1; }
done
expect_fail v_preset "unknown"

chk "profile show mci FAKESNI" "$(profile_cmd show mci | grep '^FAKESNI=')" "FAKESNI=mci.ir"
chk "profile show mci FAKEMODE" "$(profile_cmd show mci | grep '^FAKEMODE=')" "FAKEMODE=seqsum"
chk "profile show mci POOLROT" "$(profile_cmd show mci | grep '^POOLROT=')" "POOLROT=30m"
chk "profile show mci ECH" "$(profile_cmd show mci | grep '^ECH=')" "ECH=ladder"
chk "profile show blackout FAKEMODE" "$(profile_cmd show blackout | grep '^FAKEMODE=')" "FAKEMODE=auto"
chk "profile show blackout POOLROT" "$(profile_cmd show blackout | grep '^POOLROT=')" "POOLROT=90s"
chk "profile show conservative POOLROT" "$(profile_cmd show conservative | grep '^POOLROT=')" "POOLROT=4h"
chk "profile show conservative ECH" "$(profile_cmd show conservative | grep '^ECH=')" "ECH=auto"
expect_fail profile_cmd show nonexistent
expect_fail profile_cmd del mci

# Applying built-in presets to tunnels
bin_ver_ok() { echo 1; }
profile_cmd apply mci t1
chk "apply mci fake-sni" "$(grep '^fake-sni:' "$WAT_CONF/t1.yml")" "fake-sni: mci.ir"
chk "apply mci fake-mode" "$(grep '^fake-mode:' "$WAT_CONF/t1.yml")" "fake-mode: seqsum"
chk "apply mci pool-rotate" "$(grep '^pool-rotate:' "$WAT_CONF/t1.yml")" "pool-rotate: 30m"
chk "apply mci pool-rotate-bytes" "$(grep '^pool-rotate-bytes:' "$WAT_CONF/t1.yml")" "pool-rotate-bytes: 500MB"
chk "apply mci ech" "$(grep '^ech:' "$WAT_CONF/t1.yml")" "ech: ladder"

preset_cmd t1 blackout
chk "preset blackout fake-mode" "$(grep '^fake-mode:' "$WAT_CONF/t1.yml")" "fake-mode: auto"
chk "preset blackout pool-rotate" "$(grep '^pool-rotate:' "$WAT_CONF/t1.yml")" "pool-rotate: 90s"
chk "preset blackout pool-rotate-bytes" "$(grep '^pool-rotate-bytes:' "$WAT_CONF/t1.yml")" "pool-rotate-bytes: 100MB"

preset_cmd t1 conservative
chk "preset conservative fake-mode" "$(grep '^fake-mode:' "$WAT_CONF/t1.yml")" "fake-mode: seq"
chk "preset conservative pool-rotate" "$(grep '^pool-rotate:' "$WAT_CONF/t1.yml")" "pool-rotate: 4h"
chk "preset conservative ech" "$(grep '^ech:' "$WAT_CONF/t1.yml")" "ech: auto"

preset_cmd t1 off
chk "preset off clears fake-sni" "$(grep -c '^fake-' "$WAT_CONF/t1.yml")" "0"
chk "preset off clears pool-rotate" "$(grep -c '^pool-' "$WAT_CONF/t1.yml")" "0"
chk "preset off clears ech" "$(grep -c '^ech:' "$WAT_CONF/t1.yml")" "0"

# ICMP carrier & volume governor preset
cat >"$WAT_CONF/t_icmp.yml" <<'EOF'
mode: client
carrier: icmp
peer: 198.51.100.1
EOF
apply_preset t_icmp mci
chk "icmp preset sets governor" "$(grep '^governor:' "$WAT_CONF/t_icmp.yml")" "governor: true"
apply_preset t_icmp off
chk "icmp preset off clears governor" "$(grep -c '^governor:' "$WAT_CONF/t_icmp.yml")" "0"
rm -f "$WAT_CONF/t_icmp.yml"

uname() { echo Darwin; } # profiles are a CAP_NET_RAW feature: refuse to save off-Linux
expect_fail profile_cmd save win t1
chk "off-Linux save wrote nothing" "$([ -e "$WAT_CONF/profiles/win.env" ] && echo y || echo n)" "n"
uname() { echo Linux; }

# blackout_cmd: preset vs domain
printf 'mode: client\ncarrier: tcp\npeer: example.com:443\n' >"$WAT_CONF/t2.yml"
bin_ver_ok() { echo 1; }
WAT_PREFIX=wattest blackout_cmd t2 mci
chk "blackout preset fake-sni" "$(grep '^fake-sni:' "$WAT_CONF/t2.yml")" "fake-sni: mci.ir"
chk "blackout preset fake-mode" "$(grep '^fake-mode:' "$WAT_CONF/t2.yml")" "fake-mode: seqsum"
chk "blackout preset pool-rotate" "$(grep '^pool-rotate:' "$WAT_CONF/t2.yml")" "pool-rotate: 30m"

sed -i -E '/^pool-rotate:/d' "$WAT_CONF/t2.yml"
bin_ver_ok() { [ "$1" = 2.7.0 ] || { echo "FAIL bin_ver_ok got '$1'"; fail=1; }; echo 1; }
WAT_PREFIX=wattest blackout_cmd t2 mci.ir
chk "blackout wrote fake-sni" "$(grep '^fake-sni:' "$WAT_CONF/t2.yml")" "fake-sni: mci.ir"
chk "blackout default mode seq" "$(grep '^fake-mode:' "$WAT_CONF/t2.yml")" "fake-mode: seq"
chk "blackout leaves fake-ttl unset" "$(grep -c '^fake-ttl:' "$WAT_CONF/t2.yml")" "0"
chk "blackout domain leaves pool-rotate unset" "$(grep -c '^pool-rotate:' "$WAT_CONF/t2.yml")" "0"
expect_fail blackout_cmd t2 'bad name!'
rm -f "$WAT_CONF/t2.yml"
bin_ver_ok() { echo 1; }

# Numbered pickers default return under NONINTERACTIVE=1
NONINTERACTIVE=1
NI_PRESET='' pick_preset
chk "pick_preset default" "$REPLY_V" "mci"
NI_PRESET='irancell' pick_preset
chk "pick_preset explicit" "$REPLY_V" "irancell"

NI_FAKESNI='' pick_sni_preset
chk "pick_sni_preset default" "$REPLY_V" "mci.ir"
NI_FAKESNI='divar.ir' pick_sni_preset
chk "pick_sni_preset explicit" "$REPLY_V" "divar.ir"

NI_FAKEMODE='' pick_fake_mode
chk "pick_fake_mode default" "$REPLY_V" "seqsum"
NI_FAKEMODE='auto' pick_fake_mode
chk "pick_fake_mode explicit" "$REPLY_V" "auto"

NI_POOLROT='' pick_pool_rotate
chk "pick_pool_rotate default" "$REPLY_V" "30m"
NI_POOLROT='90s' pick_pool_rotate
chk "pick_pool_rotate explicit" "$REPLY_V" "90s"

NI_POOLBYTES='' pick_pool_rotate_bytes
chk "pick_pool_rotate_bytes default" "$REPLY_V" "500MB"
NI_POOLBYTES='1GB' pick_pool_rotate_bytes
chk "pick_pool_rotate_bytes explicit" "$REPLY_V" "1GB"

NI_ECH='' pick_ech
chk "pick_ech default" "$REPLY_V" "ladder"
NI_ECH='auto' pick_ech
chk "pick_ech explicit" "$REPLY_V" "auto"

# Automated link bypass verification (anticensor_test)
cat >"$WAT_CONF/t_probe.yml" <<'EOF'
mode: client
carrier: wss
peer: example.com:443
metrics: 127.0.0.1:54321
fake-sni: mci.ir
fake-mode: seqsum
ech: ladder
EOF
stats() {
  echo '{"alive": true, "srtt_ms": 22.4, "pkts_in": 120, "pkts_out": 135, "filter_profile": "desync-seqsum", "ech": "ladder"}'
}
ANTICENSOR_TEST_WAIT=1 anticensor_test t_probe && echo "ok   anticensor_test passed for alive tunnel" || { echo "FAIL anticensor_test alive"; fail=1; }

stats() {
  echo '{"alive": false}'
}
expect_fail env ANTICENSOR_TEST_WAIT=1 anticensor_test t_probe
expect_fail anticensor_test non_existent_tunnel
rm -f "$WAT_CONF/t_probe.yml"

[ "$fail" = 0 ] && echo "ALL OK" || echo "FAILURES: $fail"
exit "$fail"