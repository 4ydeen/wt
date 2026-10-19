# Agent handoff: what changed on branch `dev` (2.7.0)

Commit `d355a05` on branch `dev`, on top of `bf92665` (2.6.0) — 13 files, +1490/−209. Not merged to
`main`, not tagged, no release cut. Companion docs committed in the same commit:
`RESEARCH-2.md` (method research and ranking for the whitelisting and blackout scenarios) and
`FAKE-SNI-DESIGN.md` (the 2.6.0 design; the packet layout and fake-hello mechanics are unchanged in
2.7.0, only the *trigger* changed). This file describes every change of `d355a05` in full detail.

## Why (the 2.6.0 bug this round fixes)

The task asked for the next methods research + implementation. While re-deriving the trigger
mechanics from the reference tools, one critical 2.6.0 defect surfaced: **the fake never fired on a
normal dial.** Precisely: the 2.6.0 sniffer's `handle()` started tracking a connection only on an
outgoing SYN whose 4-tuple was *already* announced by `Wrap` — but `Wrap` runs inside the pool's
dial hook, i.e. after `dial()` returns, and the kernel's SYN (usually also the SYN-ACK and the
final ACK) is on the wire before that. The state machine's first transition never matched; no
fake was ever sent; every connection fell through the 2 s timeout unclassified. 2.7.0 is therefore
the fix plus the hardening that the research ranked first (NAT-sequence follow, auto-TTL, more
carriers).

## Reference sources used (cloned to %TEMP%\wt-research this session, since deleted)

- `patterniha/SNI-Spoofing` — `fake_tcp.py` state machine (outbound SYN → inbound SYN-ACK with
  strict ISN/ack cross-checks → outbound final ACK → fake built by mutating a copy of that ACK,
  `seq = syn_seq + 1 − len(fake)`, PSH set, `ip.ident + 1`); `main.py` hardcoded to
  `BYPASS_METHOD = "wrong_seq"` (no ttl mode shipped).
- `bol-van/zapret` — `nfq/desync.c` (3504 lines): full desync taxonomy. Informed the early/late
  trigger split (their zero-stage/second-stage) and the NAT-rewrite handling. Fake packet = fixed
  680-byte ClientHello template (SNI `www.microsoft.com`) — we deliberately keep per-build
  randomness instead (2.6.0 decision, unchanged).
- `ValdikSS/GoodbyeDPI` — same family, no extra mechanisms beyond zapret's set.
- net4people/bbs #626 — via the repo's own field records only; live web was down this session
  (web_search 401, web_fetch DNS-sunk, Invoke-WebRequest TLS-reset). git-over-HTTPS worked with
  `git -c http.sslBackend=openssl ...` — that is how the clones happened.

---

## Files changed, in full detail

### Rewritten — `wat/desync.go` (portable, builds on every OS, 435 lines)

**Unchanged from 2.6.0** (same bytes, same behavior):
- `htons(v uint16) uint16` — byte swap for socket option constants (line 25).
- `csum(b []byte) uint16` — internet checksum, shared with `icmp_linux.go` (line 28).
- `tcpChecksum(th, src, dst []byte) uint16` — pseudo-header + segment checksum (line 43).
- `FakeClientHello(sni string) []byte` — the minimal TLS 1.2-format ClientHello; record `16 03 01`,
  handshake type 1, version `03 03`, 32 crypto/rand bytes, empty session id, ciphers
  `c02b/c023`, server_name + supported_groups (x25519, secp256r1) + signature_algorithms
  (ecdsa_secp256r1_sha256) extensions; `nil` for empty SNI (line 77).
- `parseSNIOf(rec []byte) (string, error)` — test-only SNI round-trip parser (line 108).
- `desyncPeerIP(peer string) string` — now a thin wrapper over `desyncPeerHostPort` (line 157).

**New:**
- `DesyncConfig` — same three fields (SNI, Mode, TTL) with the TTL doc extended: `0 = calibrate it
  from the server's inbound TTL` (line 53).
- `validateDesync(cfg DesyncConfig) error` (line 60) — the config validation both OSes share, so
  error messages match everywhere: empty SNI → error; mode not in `""|seq|ttl` → `-fake-mode must
  be seq or ttl, got %q`; TTL `<0 || >255` → `-fake-ttl must be 0 (auto) or 1..255, got %d`.
  TTL 0 is legal in ttl mode (auto).
- `desyncPeerHostPort(peer string) (ip, port string)` (line 152, approx) — splits a host:port peer
  and resolves the host (first IPv4 A record wins), best effort like `desyncPeerIP`.
- `desyncKey` (line 185) — the outgoing 4-tuple `{srcIP, dstIP [4]byte; srcPt, dstPt uint16}`;
  inbound frames match the reversed key. Same layout as 2.6.0's injector key but moved to the
  portable file.
- `fakePacket(k desyncKey, seq, ack uint32, ttl int, hello []byte) []byte` (line 194) — the pure
  fake packet builder: IPv4 `0x45`, total length, DF (`pkt[6] = 0x40`), TTL byte 8, proto 6, the
  4-tuple's addresses, TCP header with ports, `seq`, `ack`, data offset `0x50`, flags `0x18`
  (PSH|ACK), window `0xffff`, payload = hello, checksum in place. Extraction makes the packet
  byte-pinnable in tests on any OS.
- `parseEthIPv4(frame []byte) []byte` (line 217) — returns the IPv4 packet of an ethernet frame
  (ethertype `0x0800`, version 4), else nil. Pure, so the frame-parsing path is testable off
  Linux.
- `desyncTracker` (line 247) — the portable handshake state machine; the heart of the fix. Fields:
  `cfg`, `peerIP [4]byte`, `hello` (built once by `newDesyncTracker` via `FakeClientHello`),
  `send func(pkt []byte)` (injection seam: the Linux injector sets it to its raw sender, tests set
  it to a collector), optional `logf`, `mu sync.Mutex`, `conns map[desyncKey]*desyncConn`,
  `wait map[desyncKey]chan struct{}` (channels Wrap blocks on), `peerTTLv uint8` (auto-TTL
  learning), `firedN int`, `miss/missNoted` (one-time log flag), `closed bool`.
  - `desyncConn` (line 263): `synSeq` (the ISN as the wire sees it; updated on NAT rewrite),
    `isnKnown` (early vs late mode), `synAckSeq`, `synAckAck` (the server's ISN+1 as seen on the
    wire), `at` timestamp.
  - `newDesyncTracker(cfg, peerIP [4]byte) *desyncTracker` (line 272).
  - `announce(k desyncKey, isn uint32, known bool) chan struct{}` (line 279) — Wrap registers a
    connection and gets its wait channel; `known=true` = early mode with the probed stream start
    in `isn`; `known=false` = late mode. After `close()`, announces return closed channels at
    once.
  - `abandon(k)` (line 293) — drops a connection whose Wrap timed out: closes the wait channel
    (releasing Wrap) and forgets the conn, so a late wire event can no longer fire a fake for it.
  - `close()` (line 303) — idempotent: closes all wait channels, drops all conns; handleIPv4
    becomes a no-op.
  - `fired() int` / `peerTTL() uint8` — test/observation accessors.
  - `handleIPv4(ip []byte)` (line 331) — the state machine, one raw IPv4 packet per call
    (header included; the Linux loop strips the ethernet header with `parseEthIPv4` first).
    Parsing guards: IPv4, proto TCP, IHL ≥ 20, TCP offset ≥ 20, length checks. Reads
    seq/ack/flags (SYN/ACK/RST) and payload length. Then, under one lock:
    1. **TTL learning** (line 364): any inbound SYN-ACK from the peer IP (tracked or not) with no
       payload and not RST sets `peerTTLv = ip[8]` — once, since it only fills when still 0.
    2. **Outgoing SYN on a tracked key** (line 368): (re)learns the ISN from the wire; a different
       seq on a later SYN resets the learned SYN-ACK state (fresh handshake on the same tuple);
       marks `isnKnown = true`. Note: a conn is only tracked if `announce` ran first — the
       announce happens after dial, so on most dials this branch does *not* fire (the SYN is long
       gone); that is fine, the two paths below cover it.
    3. **Inbound SYN-ACK for a tracked conn** (line 376): remembers `synAckSeq`/`synAckAck`; and
       the NAT follow: if `isnKnown` and the SYN-ACK's ack differs from `synSeq+1`, a uniform NAT
       rewrite happened → `synSeq = ackv - 1`, so the fake's base and its "below stream start"
       property hold **as the server sees it**. This is the seq-mode field failure from January
       2026 made survivable (uniform rewrites only; non-uniform normalization still defeats any
       client-side fake — RESEARCH-2 §1.1).
    4. **Fire conditions** (line 390):
       - early (`isnKnown`): any outbound ACK-carrying, non-SYN segment whose seq is at or after
         the stream start (`seq - synSeq + 1 < 0x80000000`, wrap-safe comparison) fires with
         `base = synSeq + 1` and `ack = the segment's ack` — the final handshake ACK normally, or
         the first data segment if the final ACK was never observed (the 2.6.0 killer case).
       - late (`!isnKnown`): the first outbound **data** segment (payload > 0, ACK, no SYN) fires
         with `base = its seq` — the segment's own sequence number IS the stream start. Bare ACKs
         never fire (pinned by `TestDesyncLateNeedsData`). Gating: needs either `synAckAck != 0`
         (a SYN-ACK was seen, so the fake can ack the server's SYN plausibly) or `isnKnown`
         (line 387).
  - `fireLocked(k, c, base, ack uint32)` (line 405) — mu held by caller. TTL selection: seq mode →
    64; ttl mode → `cfg.TTL`, and when that is ≤ 0 (auto) → `peerTTLv − 1`, or, if the peer TTL
    was never learned, `miss++` + one log line and **no fire** (degrade: Wrap still gets released
    via abandon on timeout; the tunnel works unclassified). Then: `firedN++`, delete the conn and
    its wait entry, close the wait channel (releasing Wrap), and — exactly once per connection —
    `send(fakePacket(k, base − len(hello), ack, ttl, hello))`.

**Removed from 2.6.0 (moved into the tracker):** `Desync`/`desyncInjector`/`desyncConn` state
machine and `fire()` (Linux file), the `handle()` method, the per-injector `announce` with fixed
`known` semantics.

### Rewritten — `wat/desync_linux.go` (Linux only, 176 lines)

- `desyncWrapTimeout = 2 * time.Second` (line 29) — how long Wrap waits for the fake.
- `tcpStreamBase(tc *net.TCPConn) (nxt uint32, ok bool)` (line 35) — NEW probe, the piece that
  makes the early path work after dial returns. Sequence: `tc.SyscallConn()` → `Control` →
  `setsockopt(TCP_REPAIR, 1)` → defer `setsockopt(TCP_REPAIR, 0)` → `setsockopt(TCP_REPAIR_QUEUE,
  1 /* TCP_SEND_QUEUE */)` → raw `Syscall6(SYS_GETSOCKOPT, fd, IPPROTO_TCP, TCP_QUEUE_SEQ, &b,
  &l=4)` (x/sys/unix has no TCP_QUEUE_SEQ wrapper; 4 bytes, little-endian read) → `TCP_REPAIR` off
  via the defer. Returns the send-queue sequence number (SND.NXT = stream start right after the
  handshake). `ok=false` on any failure — the probe needs **CAP_NET_ADMIN** (CAP_NET_RAW alone is
  not enough for TCP_REPAIR); the caller then uses the late path. Non-invasive: repair mode only
  freezes queue accounting; buffers untouched; the socket keeps working.
- `Desync` struct `{inj *desyncInjector}` (line 67) — same public shape as 2.6.0.
- `NewDesync(cfg DesyncConfig, peer string) (*Desync, error)` (line 72): `validateDesync` first
  (identical error messages on every OS), then `desyncPeerHostPort` + `net.ParseIP` — requires an
  IPv4 peer (`wat: desync needs an IPv4 -peer`), then `newDesyncInjector`.
- `Wrap(c net.Conn) (net.Conn, error)` (line 93): non-TCPConn passes through; non-IPv4 addrs pass
  through; otherwise builds the outgoing `desyncKey`, probes `tcpStreamBase`, `announce`s with
  `(isn, known)`, then `select` on the wait channel vs `time.After(desyncWrapTimeout)`; on timeout
  `abandon(k)`. Always returns the original conn — timeout degrades to unclassified, never to a
  broken tunnel.
- `Close()` (line 118) — `sync.Once`-guarded: `tr.close()` then `unix.Close(fd)`.
- `desyncInjector` (line 123) — now a thin shell: `{tr *desyncTracker, fd int, closed sync.Once}`.
- `newDesyncInjector(cfg, peerIP [4]byte)` (line 130): one `AF_PACKET`/`SOCK_RAW|SOCK_NONBLOCK`
  socket on `ETH_P_ALL` (error wrapped: `wat: -fake-sni needs CAP_NET_RAW: %w`), tracker built,
  `tr.send = d.sendRaw` (the injection seam), reader goroutine started.
- `loop()` (line 149): nonblocking `unix.Read` into a 2048-byte buffer; EAGAIN/EINTR continue;
  anything else → 10 ms backoff (Wrap's timeout governs); successful reads go through
  `parseEthIPv4` → `tr.handleIPv4`.
- `sendRaw(pkt []byte)` (line 168): unchanged from 2.6.0 — one throwaway `IPPROTO_RAW` socket
  (IP_HDRINCL; the kernel fills the IP checksum) per fire, `Sendto` with the packet's own dst.

### Rewritten — `wat/desync_other.go` (`!linux`, 22 lines)

- `NewDesync` runs `validateDesync(cfg)` FIRST — a bad mode/SNI/TTL fails identically off-Linux —
  and only then returns the platform error `wat: -fake-sni needs Linux with CAP_NET_RAW (the ICMP
  carrier's requirement)`. `Desync` struct + `Wrap`/`Close` no-op stubs unchanged (they only exist
  so `cmd/wattun` compiles).

### Rewritten — `wat/desync_test.go` (16 tests, 498 lines, all pass on Windows)

Test helpers (portable, so the whole state machine is tested off-Linux):
- `desyncTestPkt(...)` (line 156) — builds one raw IPv4+TCP packet exactly as the wire delivers it
  (checksum in place), so `handleIPv4` sees realistic input.
- flag consts `testFlagFIN/RST/PSH/ACK/SYN` (line 177).
- `desyncTestTracker(mode string, ttl int)` (line 186) — tracker with SNI `mci.ir` and a
  collecting `send` (`sent *[][]byte`); peer IP 10.8.0.1.
- `testClientKey()` (line 203) — the fixed test 4-tuple 192.168.1.2:5000 → 10.8.0.1:443.
- `feedFullHandshake(tr, k, isn, srvSeq)` (line 211) — drives SYN (client) → SYN-ACK (server, TTL
  52) → final ACK into the tracker.

Kept from 2.6.0 (unchanged): `TestFakeClientHelloRealParser` (feeds the fake to a stdlib
`crypto/tls` TLS 1.2 server; pass = record+hello parse cleanly and the handshake advances —
net.Error / AlertError / EOF / ErrClosedPipe accepted, parse rejection fails),
`TestFakeClientHello` (SNI round-trip ×3 names, record length consistency, per-build randomness,
empty SNI → nil), `TestDesyncSeqBefore` (seq arithmetic pin), `TestDesyncPeerIP`,
`TestTCPChecksum` (folded-sum self-consistency).

New (each pins one mechanic of the tracker):
1. `TestValidateDesync` — seq ok, ttl ok, ttl+TTL 0 ok (auto), empty SNI fails, bad mode fails,
   TTL 300 fails.
2. `TestDesyncEarlyFiresBeforeData` — announce(isn+1, known) → full handshake → exactly one fake;
   pins: packet length (40+len(hello)), seq = isn+1−len(hello), ack = server ISN+1, TTL 64 in seq
   mode, ports of the 4-tuple, `fired()` == 1.
3. `TestDesyncEarlyFiresOnFirstData` — wrap-prone ISN 0xffff0000; first data segment arrives
   before any final ACK was seen → fake still fires with base = stream start (the 2.6.0 killer
   case).
4. `TestDesyncLateFiresOnData` — announce(0, known=false), sniffer missed the SYN; SYN-ACK + first
   data → fires anchored to the data segment's seq.
5. `TestDesyncLateNeedsData` — late mode: SYN-ACK + two bare ACKs → **no** fire.
6. `TestDesyncNATRewrite` — SYN with ISN 1000, SYN-ACK acking 2001 (NAT rewrote to ISN 2000) →
   fake seq = 2000+1−len(hello): the fake follows the NAT-shifted base as the server sees it.
7. `TestDesyncTTLCalibration` — ttl mode, TTL 0; SYN-ACK arrives with IP TTL 52 → fake goes out
   with TTL 51 (one hop short of the server).
8. `TestDesyncTTLCalibratedBeforeHandshake` — a stray SYN-ACK from the peer on another port
   pre-learns TTL 60 → subsequent handshake fires with TTL 59 immediately.
9. `TestDesyncTTLCalibratedNotYet` — ttl auto, no SYN-ACK seen → no fire; `abandon` releases the
   waiting Wrap channel.
10. `TestDesyncFixedTTL` — ttl mode, TTL 9 → fake TTL 9 (explicit value used as-is).
11. `TestDesyncOneFakePerConn` — post-fire segments (data, ACKs) never fire again.
12. `TestDesyncUnknownConnIgnored` — a full handshake on a never-announced tuple → no fire.
13. `TestDesyncFakePacketRoundTrip` — built fake parses via `parseEthIPv4` (dst IP, TTL byte),
    TCP checksum recomputes to the stored value (zero → compare → restore), payload identity with
    `FakeClientHello("mci.ir")`.
14. `TestDesyncAbandonAndClose` — abandon closes the wait channel at once; after `close()`,
    announce returns a closed channel and nothing fires.
15. `TestDesyncParseEthIPv4` — ARP frame and short frame rejected.

### Modified — `cmd/wattun/main.go` (3 hunks)

- `attachFakeSNI` (line 204, closure inside `main()` because it reads the flag locals): unchanged
  logic — builds one `wat.Desync` per peer and installs it as the pool's dial hook (`SetDialHook`)
  — but its comment now says the carrier scope; and it is now called in one more place:
  - line 268: `tcp` carrier client case (2.6.0 behavior kept);
  - line 287: `tls` carrier client case (2.6.0 behavior kept);
  - line 328: NEW — after the `ws|wss|h2|h2c|grpc` client switch builds its pool client
    (`NewWSPoolClient`/`NewGRPCPoolClient`/`NewH2PoolClient`), `attachFakeSNI(pc, peer)` runs on
    success. All five dial through `TCPPoolClient` slots, so the dial hook covers every
    connection including lazy redials. (`h2c` rides along but is pointless there — a cleartext h2
    flow has no TLS shape for the fake to imitate.)
- Flag help text (lines 85-87): `-fake-sni` now lists `tcp|tls|wss|h2|grpc` and says the sniffer
  tracks outgoing handshakes on the wire; `-fake-mode` ttl says `needs -fake-ttl N or 0 =
  calibrate it once with traceroute before the first fake` — corrected to reflect that 0 means
  auto-calibration from the peer's SYN-ACKs; `-fake-ttl` help ends with `0 = calibrate once from
  the server's replies`.
- No config.go change: config keys derive from flags via `flag.Lookup` (project convention).

### Docs + version

- `docs/TECHNICAL.md`:
  - "Fake-SNI desync (`fake-sni`, 2.6.0)" section (Carriers chapter): added the 2.7.0 paragraph —
    wire-watch trigger anchored to final ACK or first data segment, NAT-follow, carriers
    `tcp`/`tls`/`wss`/`h2`/`grpc`, `fake-ttl: 0` auto-calibration.
  - "Fake-SNI desync (whitelisting survival)" section: carrier list extended, `fake-mode: seq`
    bullet now says a uniform NAT rewrite shifts the fake with it (2.7.0), `fake-mode: ttl` bullet
    documents `fake-ttl: 0` auto.
  - Flag/config table: the three fake-* rows existed TWICE (2.6.0 doc bug) — collapsed to one set;
    `fake-ttl` row documents 0 = auto since 2.7.0.
  - Release history: new `2.7.0` entry (trigger fix explained in user terms, NAT follow, auto-TTL,
    carrier scope, client-only/server-unchanged/no wire change) above the 2.6.0 entry.
- `README.md`: badge → `release-v2.7.0`; intro sentence names the 2.7.0 scope (wss/h2/grpc +
  auto-TTL + NAT follow).
- `README.fa.md`: same two changes; Farsi prose inside `<div dir="rtl">`, Persian digits
  (۲٫۷٫۰), written natively (not translated).
- `wat/version.go`: `Version = "2.7.0"`.

---

## Compatibility and performance invariants

- **Wire compatibility: unchanged.** The fake is a raw packet injected next to the flow; server,
  session, frames, crypto untouched. No new frame types. Old server + new client and vice versa
  work. (The `h2c` carrier accepts the flag but gains nothing — cleartext flow.)
- **ICMP path: untouched.** No diff in `session.go`, `cc.go`, `sched.go`, `fec.go`,
  `icmp_linux.go`, `carrier_tcp.go`, `carrier_udp.go` — the sim tests' pins are not at risk from
  this round's diffs.
- **Non-Linux:** compiles; `-fake-sni` fails at startup with the same platform error as 2.6.0
  (after running the shared config validation first, so a bad `-fake-mode` errors identically
  everywhere).

## Verification status (this Windows box)

- `go build ./...` ✅ · `go vet ./...` ✅ · `GOOS=linux go build ./...` ✅
- `go test -count=1 ./cmd/...` — 29 pass ✅
- Desync tests 16/16 ✅:
  `go test -count=1 -run 'TestDesync|TestFake|TestValidateDesync|TestTCPChecksum' ./wat/`
- `go test -count=1 -run 'TestTwoClientsSameKey|TestFairQueueUngroupedIsPerStream' ./wat/` — pass
  (the two tests the 2.6.0 handoff saw time out under load; healthy alone here).
- `GOOS=linux go test` cannot *execute* on Windows (linux/amd64 test binary) — build-only check.
- **Environment notes for the next agent on this Windows box:**
  - The pwsh tool runs at Low integrity: it cannot write `%LOCALAPPDATA%\go-build`, the Go module
    cache, or `.git/index.lock`. Go needs workspace-local caches:
    ```powershell
    $env:GOCACHE="$PWD\.gocache"; $env:GOMODCACHE="$PWD\.gomodcache"; $env:GOPATH="$PWD\.gopath"
    ```
  - `git commit`/`git add` from the sandboxed shell fail with `index.lock: Permission denied` —
    the commit was made via one sandbox-approved unconfined run; expect the same and escalate
    once if you commit.
  - `.gocache/ .gomodcache/ .gopath/ .acl-recovery/` are untracked artifacts of that setup; safe
    to delete or `.gitignore`.
- Full `wat/` suite: NOT run to completion (known ~5 min + this box's load flakiness — times out
  on clean `main` too; same caveat as the 2.6.0 handoff). Re-run with `-timeout 600s` on a quiet
  Linux box; nothing this round touches session/cc/ICMP.
- Linux raw-socket behavior (`tcpStreamBase` probe under real CAP_NET_ADMIN, real AF_PACKET
  sniffing, `sendRaw`) not exercised on Windows — needs a Linux host with CAP_NET_RAW
  (+ CAP_NET_ADMIN for the probe). Untested-on-hardware, flagged.

## Not done / next steps for another agent

1. **Field-validate on an Iran path** (the queue, in order): does the early path fire on tcp and
   tls carriers (fake visible at the censor); does `fake-ttl: 0` calibrate; does the NAT-follow
   rescue an ISP where 2.6.0/seq died.
2. If fake-SNI gets blocked while TCP still passes: implement RESEARCH-2 §1.2 — real-ClientHello
   disorder (zapret multisplit/multidisorder). The tracker's `send` hook is the injection point;
   a split-point resolver + segment builder slots next to `fakePacket`.
3. Blackout scenario: write the domestic-relay chain recipe (RESEARCH-2 §2.2 — two wattun
   instances, server role on a domestic box) into TECHNICAL.md after field-checking domestic VPS
   availability. No code needed.
4. Push `dev`, tag `v2.7.0` → release workflow; after it finishes
   `gh release edit v2.7.0 --notes-file <file>`. Client-only update; server unchanged; no wire
   change; mixed versions fine.
5. Optional: teach `wattun-manager` the fake-sni flags (config keys already derive).
6. Optional: `.gitignore` for `.gocache/.gomodcache/.gopath/.acl-recovery`.
7. Optional (flagged): IPv6 in the injector — still IPv4-only by design, same as the reference
   tool; add only if a real deployment needs it.
