#!/usr/bin/env bash
# self-check for wattun-manager: resilience profiles (profile save/list/show/del/apply), the wizard's
# profile defaults, the unattended flags (--fake-sni/--fake-mode/--fake-ttl/--pool-rotate/--pool-rotate-bytes)
# and the value validators. No root, no systemd, no binary needed.
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
expect_fail ni_parse --pool-rotate 30x
expect_fail ni_parse --fake-mode gq
expect_fail ni_parse --pool-rotate-bytes 20QQ
expect_fail ni_parse --fake-ttl 999
v_pool_rotate off && echo "ok   v_pool_rotate off" || { echo "FAIL v_pool_rotate off"; fail=1; }
for v in 500MB 4G 300k 1.5gb 0b 0 off; do v_pool_bytes "$v" && echo "ok   v_pool_bytes $v" || { echo "FAIL v_pool_bytes $v"; fail=1; }; done

[ "$fail" = 0 ] && echo "ALL OK" || echo "FAILURES: $fail"
exit "$fail"