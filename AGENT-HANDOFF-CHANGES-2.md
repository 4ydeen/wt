# Agent handoff: what changed on branch `dev` (2.7.0)

Commit on branch `dev` (see `git log`), on top of `bf92665` (2.6.0). Not merged to `main`, not
tagged, no release cut. Companion docs: `RESEARCH-2.md` (the method research and ranking this
round produced) and `FAKE-SNI-DESIGN.md` (the 2.6.0 design, still accurate for the mechanics).

## Why

Task: research and design the next anti-blackout methods for two scenarios (whitelisting again;
full blackout), implement the top-ranked ones. While re-deriving the trigger mechanics from the
reference tools (patterniha/SNI-Spoofing and zapret sources were cloned and read; see RESEARCH-2
§0), one **critical 2.6.0 bug** surfaced: the fake never actually fired on a normal dial.

The 2.6.0 bug, precisely: the sniffer only tracked handshakes for 4-tuples that `Wrap` had already
announced, but `Wrap` runs after `dial()` returns — the kernel's SYN (and usually SYN-ACK and the
final ACK) are already on the wire by then. The state machine's first two transitions never
matched; every connection fell through the 2 s timeout unclassified. So 2.7.0 = bug fix + the
hardening the research ranked first (NAT-follow, auto-TTL, more carriers).

## Reference sources used (cloned to %TEMP%\wt-research this session, gone after)

- `patterniha/SNI-Spoofing` — wrong-seq fake, WinDivert state machine (fake_tcp.py), strict
  ISN/ack cross-checks, fake built by mutating a copy of the final ACK.
- `bol-van/zapret` (nfq/desync.c) — full desync taxonomy; informed the early/late trigger split
  (their zero-stage/second-stage) and the NAT-rewrite observation.
- `ValdikSS/GoodbyeDPI` — same family, no extra mechanisms.
- net4people/bbs #626 — via the repo's own field records only; live web was down this session
  (web_search 401, web_fetch DNS-sunk, Invoke-WebRequest TLS-reset; git-over-HTTPS with
  `http.sslBackend=openssl` worked, which is how the clones happened).

## Files changed

### Rewritten — `wat/desync.go` (portable, testable everywhere)

- `DesyncConfig` unchanged (SNI/Mode/TTL); new `validateDesync(cfg)` shared by every OS: TTL now
  0..255, 0 = auto-calibrate in ttl mode.
- `desyncTracker` — the portable handshake state machine, fed raw IPv4 packets via `handleIPv4`:
  - *early path*: announced with a known stream start (probed SND.NXT) → fires on the handshake's
    final ACK **or the first outbound data segment**, whichever comes first (the 2.6.0 fix:
    anything at/after the stream start triggers, so a missed final ACK no longer loses the fake).
  - *late path*: announced with `known=false` → fires anchored to the first outbound **data**
    segment (its seq IS the stream start); never fires on bare ACKs.
  - NAT follow: the SYN-ACK's ack is cross-checked against the announced ISN; a uniform rewrite
    shifts the fake's base (`c.synSeq = ackv - 1`), so seq mode survives the field failure that
    killed it in January 2026.
  - Auto-TTL: any SYN-ACK from the peer IP teaches `peerTTLv`; ttl mode with TTL 0 sends the fake
    with `peerTTL − 1` (logs once if not learned yet, handshake stays unclassified — degrade, not
    break).
  - `announce`/`abandon`/`close` manage Wrap wait channels; exactly one fake per connection
    (`firedN`, conn deleted after fire); unannounced 4-tuples ignored; RST stops tracking.
- `fakePacket(k, seq, ack, ttl, hello)` — pure packet builder (IPv4+TCP+hello, DF, PSH|ACK, valid
  checksum); extracted so tests pin it byte-for-byte.
- `parseEthIPv4(frame)` — ethernet→IPv4 extraction, also pure.
- `desyncPeerHostPort` added (peer split used by NewDesync); `desyncPeerIP` unchanged behavior.
- Unchanged: `htons`, `csum`, `tcpChecksum`, `FakeClientHello`, `parseSNIOf`.

### Rewritten — `wat/desync_linux.go` (Linux only)

- Same AF_PACKET SOCK_RAW|SOCK_NONBLOCK sniffer on ETH_P_ALL, nonblocking read loop, feeds
  `parseEthIPv4` → `tr.handleIPv4`; `sendRaw` unchanged (IPPROTO_RAW per fire).
- NEW `tcpStreamBase(tc)`: probes the socket's SND.NXT via TCP_REPAIR(1) → TCP_REPAIR_QUEUE=
  TCP_SEND_QUEUE(1) → raw getsockopt TCP_QUEUE_SEQ (x/sys has no wrapper, so a Syscall6 with a
  4-byte LE read), TCP_REPAIR(0) in a defer. Needs CAP_NET_ADMIN (CAP_NET_RAW alone is not
  enough for TCP_REPAIR); on failure Wrap announces with `known=false` and the tracker's late
  path takes over — no hard dependency.
- `Wrap` announces with the probe result, waits ≤ 2 s (`desyncWrapTimeout`), abandons the key on
  timeout (releases Wrap; the tracker forgets the conn). Non-IPv4/non-TCP conns pass through.
- The sniffer no longer needs to see the SYN: SYN/SYN-ACK are used when available (NAT follow,
  TTL calibration), but the final-ACK/first-data anchors work without them.

### Rewritten — `wat/desync_other.go`

- `NewDesync` runs `validateDesync` FIRST (so a bad mode/SNI errors identically off-Linux), then
  the "needs Linux with CAP_NET_RAW" error. `Desync`/`Wrap`/`Close` stubs unchanged.

### Rewritten — `wat/desync_test.go` (5 → 16 tests, all pass on Windows)

Kept: `TestFakeClientHelloRealParser` (stdlib TLS server accepts the fake),
`TestFakeClientHello`, `TestDesyncSeqBefore`, `TestDesyncPeerIP`, `TestTCPChecksum`.
New (portable tracker, synthetic handshakes via `desyncTestPkt`/`feedFullHandshake`):
`TestValidateDesync`, `TestDesyncEarlyFiresBeforeData` (seq math + ack + ttl + ports pinned),
`TestDesyncEarlyFiresOnFirstData` (wrap-prone ISN 0xffff0000), `TestDesyncLateFiresOnData`,
`TestDesyncLateNeedsData` (bare ACKs must not fire), `TestDesyncNATRewrite` (fake follows the
NAT-shifted base), `TestDesyncTTLCalibration` (52 → 51), `TestDesyncTTLCalibratedBeforeHandshake`
(stray SYN-ACK pre-learns), `TestDesyncTTLCalibratedNotYet` (no fake, abandon releases Wrap),
`TestDesyncFixedTTL`, `TestDesyncOneFakePerConn`, `TestDesyncUnknownConnIgnored`,
`TestDesyncFakePacketRoundTrip` (checksum + parseEthIPv4 + payload identity),
`TestDesyncAbandonAndClose`, `TestDesyncParseEthIPv4`.

### Modified — `cmd/wattun/main.go`

- `attachFakeSNI` now also wired into the `ws|wss|h2|h2c|grpc` client case (after the pool client
  builds; h2c rides along but is pointless there — no TLS-looking flow). Flag help for
  `-fake-sni`, `-fake-mode`, `-fake-ttl` updated (carriers list, ttl 0 = calibrate).
- Config keys still auto-derive via flag.Lookup — no config.go change needed.

### Docs + version

- `docs/TECHNICAL.md`: fake-SNI section (both) updated for 2.7.0 (trigger paths, NAT follow,
  auto-TTL, carrier scope tcp/tls/wss/h2/grpc); the duplicated fake-sni/fake-mode/fake-ttl rows in
  the flag table collapsed to one set; `fake-ttl` row documents 0 = auto; release-history 2.7.0
  entry added.
- `README.md` / `README.fa.md`: badge → v2.7.0, intro sentence extended (Farsi in `<div dir="rtl">`,
  Persian digits ۲٫۷٫۰).
- `wat/version.go` → `2.7.0`.

## Wire compatibility

Unchanged, deliberately: the fake is a raw packet next to the flow; the server, session, frames,
crypto untouched. Old server + new client and vice versa work. No new frame types. The ICMP path
is untouched (its sim tests are the pin; none of this round's diffs are in the session/cc/carrier
hot paths — carrier_tcp.go is untouched this round).

## Verification status (this Windows box)

- `go build ./...` ✅ · `go vet ./...` ✅ · `GOOS=linux go build ./...` ✅
- `go test -count=1 ./cmd/...` — 29 pass ✅
- Desync tests 16/16 ✅ (`go test -count=1 -run 'TestDesync|TestFake|TestValidateDesync|TestTCPChecksum' ./wat/`)
- NOTE: run Go with workspace-local caches — the shell runs at Low integrity and cannot write
  `$env:LOCALAPPDATA\go-build` or the module cache:
  ```powershell
  $env:GOCACHE="$PWD\.gocache"; $env:GOMODCACHE="$PWD\.gomodcache"; $env:GOPATH="$PWD\.gopath"
  ```
  `.gocache/.gomodcache/.gopath/.acl-recovery` are untracked build/repair artifacts; safe to delete
  or ignore (consider .gitignore entries).
- Full `wat/` suite: NOT run to completion (known ~5 min + this box's load flakiness, times out on
  clean main too — same caveat as the 2.6.0 handoff). Re-run with `-timeout 600s` on a quiet Linux
  box; nothing this round touches session/cc/ICMP.
- Linux raw-socket behavior (tcpStreamBase probe, real sniffing) not exercised on Windows — needs
  a Linux host with CAP_NET_RAW (+ CAP_NET_ADMIN for the probe). Untested-on-hardware, flagged.

## Not done / next steps for another agent

1. Field-validate on an Iran path: does the early path fire (fake visible at the censor) on tcp and
   tls carriers; does auto-TTL calibrate (`fake-ttl: 0`); does the NAT-follow rescue an ISP where
   2.6.0/seq died.
2. RESEARCH-2 §1.2 (real-ClientHello disorder, zapret multisplit/multidisorder) is the designed
   next method if fake-SNI gets blocked while TCP passes; the tracker's `send` hook is the
   injection point.
3. RESEARCH-2 §2.2: document the domestic-relay chain recipe (two wattun instances) after field
   checking domestic VPS availability.
4. Push `dev`, tag `v2.7.0` → release workflow; then `gh release edit v2.7.0 --notes-file <file>`
   (client-only update; server unchanged; no wire change; both ends SHOULD update eventually but
   nothing breaks mixed).
5. Optional: teach `wattun-manager` the fake-sni flags (config keys already derive).
6. Optional: `.gitignore` for `.gocache/.gomodcache/.gopath/.acl-recovery`.
