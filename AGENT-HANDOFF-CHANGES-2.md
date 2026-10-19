# Agent handoff: what changed on branch `dev` (2.7.0 + 2.7.1)

Branch `dev` now carries TWO commits on top of `bf92665` (2.6.0):

- `d355a05` â€” **2.7.0** "fake-sni desync hardened and fixed: the marker now actually fires" (13 files,
  +1490/âˆ’209), with `RESEARCH-2.md` (method research for the whitelisting and Restricted-routing scenarios)
  and `FAKE-SNI-DESIGN.md` (2.6.0 design; packet layout and marker-hello mechanics unchanged, only the
  trigger changed) committed alongside.
- `a03ba93` â€” the first full-detail handoff (this file, round 1).
- `27ccdf3` â€” **2.7.1** "fake-mode sum, ISN probe fix, manager fake-sni support" (11 files,
  +301/âˆ’30): the top-ranked next steps from the round-1 handoff, all done â€” see the 2.7.1 section
  below for the full per-symbol map.

Not merged to `main`, not tagged, no release cut. Everything below describes both commits in full
detail; round-1 content (2.7.0) comes first, 2.7.1 after it.

## Why (the 2.6.0 bug this round fixes)

The task asked for the next methods research + implementation. While re-deriving the trigger
mechanics from the reference tools, one critical 2.6.0 defect surfaced: **the marker packet was never sent on a
normal dial.** Precisely: the 2.6.0 sniffer's `handle()` started tracking a connection only on an
outgoing SYN whose 4-tuple was *already* announced by `Wrap` â€” but `Wrap` runs inside the pool's
dial hook, i.e. after `dial()` returns, and the kernel's SYN (usually also the SYN-ACK and the
final ACK) is on the wire before that. The state machine's first transition never matched; no
marker was ever sent; every connection fell through the 2 s timeout unclassified. 2.7.0 is therefore
the fix plus the hardening that the research ranked first (NAT-sequence follow, auto-TTL, more
carriers).

## Reference sources used (cloned to %TEMP%\wt-research this session, since deleted)

- `patterniha/SNI-Spoofing` â€” `fake_tcp.py` state machine (outbound SYN â†’ inbound SYN-ACK with
  strict ISN/ack cross-checks â†’ outbound final ACK â†’ marker built by mutating a copy of that ACK,
  `seq = syn_seq + 1 âˆ’ len(marker)`, PSH set, `ip.ident + 1`); `main.py` hardcoded to
  `BYPASS_METHOD = "wrong_seq"` (no ttl mode shipped).
- `bol-van/zapret` â€” `nfq/desync.c` (3504 lines): full desync taxonomy. Informed the early/late
  trigger split (their zero-stage/second-stage) and the NAT-rewrite handling. Marker packet = fixed
  680-byte ClientHello template (SNI `www.microsoft.com`) â€” we deliberately keep per-build
  randomness instead (2.6.0 decision, unchanged).
- `ValdikSS/GoodbyeDPI` â€” same family, no extra mechanisms beyond zapret's set.
- net4people/bbs #626 â€” via the repo's own field records only; live web was down this session
  (web_search 401, web_fetch DNS-sunk, Invoke-WebRequest TLS-reset). git-over-HTTPS worked with
  `git -c http.sslBackend=openssl ...` â€” that is how the clones happened.

---

## Files changed, in full detail

### Rewritten â€” `wat/desync.go` (portable, builds on every OS, 435 lines)

**Unchanged from 2.6.0** (same bytes, same behavior):
- `htons(v uint16) uint16` â€” byte swap for socket option constants (line 25).
- `csum(b []byte) uint16` â€” internet checksum, shared with `icmp_linux.go` (line 28).
- `tcpChecksum(th, src, dst []byte) uint16` â€” pseudo-header + segment checksum (line 43).
- `FakeClientHello(sni string) []byte` â€” the minimal TLS 1.2-format ClientHello; record `16 03 01`,
  handshake type 1, version `03 03`, 32 crypto/rand bytes, empty session id, ciphers
  `c02b/c023`, server_name + supported_groups (x25519, secp256r1) + signature_algorithms
  (ecdsa_secp256r1_sha256) extensions; `nil` for empty SNI (line 77).
- `parseSNIOf(rec []byte) (string, error)` â€” test-only SNI round-trip parser (line 108).
- `desyncPeerIP(peer string) string` â€” now a thin wrapper over `desyncPeerHostPort` (line 157).

**New:**
- `DesyncConfig` â€” same three fields (SNI, Mode, TTL) with the TTL doc extended: `0 = calibrate it
  from the server's inbound TTL` (line 53).
- `validateDesync(cfg DesyncConfig) error` (line 60) â€” the config validation both OSes share, so
  error messages match everywhere: empty SNI â†’ error; mode not in `""|seq|ttl` â†’ `-fake-mode must
  be seq or ttl, got %q`; TTL `<0 || >255` â†’ `-fake-ttl must be 0 (auto) or 1..255, got %d`.
  TTL 0 is legal in ttl mode (auto).
- `desyncPeerHostPort(peer string) (ip, port string)` (line 152, approx) â€” splits a host:port peer
  and resolves the host (first IPv4 A record wins), best effort like `desyncPeerIP`.
- `desyncKey` (line 185) â€” the outgoing 4-tuple `{srcIP, dstIP [4]byte; srcPt, dstPt uint16}`;
  inbound frames match the reversed key. Same layout as 2.6.0's injector key but moved to the
  portable file.
- `fakePacket(k desyncKey, seq, ack uint32, ttl int, hello []byte) []byte` (line 194) â€” the pure
  marker packet builder: IPv4 `0x45`, total length, DF (`pkt[6] = 0x40`), TTL byte 8, proto 6, the
  4-tuple's addresses, TCP header with ports, `seq`, `ack`, data offset `0x50`, flags `0x18`
  (PSH|ACK), window `0xffff`, payload = hello, checksum in place. Extraction makes the packet
  byte-pinnable in tests on any OS.
- `parseEthIPv4(frame []byte) []byte` (line 217) â€” returns the IPv4 packet of an ethernet frame
  (ethertype `0x0800`, version 4), else nil. Pure, so the frame-parsing path is testable off
  Linux.
- `desyncTracker` (line 247) â€” the portable handshake state machine; the heart of the fix. Fields:
  `cfg`, `peerIP [4]byte`, `hello` (built once by `newDesyncTracker` via `FakeClientHello`),
  `send func(pkt []byte)` (injection seam: the Linux injector sets it to its raw sender, tests set
  it to a collector), optional `logf`, `mu sync.Mutex`, `conns map[desyncKey]*desyncConn`,
  `wait map[desyncKey]chan struct{}` (channels Wrap blocks on), `peerTTLv uint8` (auto-TTL
  learning), `firedN int`, `miss/missNoted` (one-time log flag), `closed bool`.
  - `desyncConn` (line 263): `synSeq` (the ISN as the wire sees it; updated on NAT rewrite),
    `isnKnown` (early vs late mode), `synAckSeq`, `synAckAck` (the server's ISN+1 as seen on the
    wire), `at` timestamp.
  - `newDesyncTracker(cfg, peerIP [4]byte) *desyncTracker` (line 272).
  - `announce(k desyncKey, isn uint32, known bool) chan struct{}` (line 279) â€” Wrap registers a
    connection and gets its wait channel; `known=true` = early mode with the probed stream start
    in `isn`; `known=false` = late mode. After `close()`, announces return closed channels at
    once.
  - `abandon(k)` (line 293) â€” drops a connection whose Wrap timed out: closes the wait channel
    (releasing Wrap) and forgets the conn, so a late wire event can no longer fire a marker packet for it.
  - `close()` (line 303) â€” idempotent: closes all wait channels, drops all conns; handleIPv4
    becomes a no-op.
  - `fired() int` / `peerTTL() uint8` â€” test/observation accessors.
  - `handleIPv4(ip []byte)` (line 331) â€” the state machine, one raw IPv4 packet per call
    (header included; the Linux loop strips the ethernet header with `parseEthIPv4` first).
    Parsing guards: IPv4, proto TCP, IHL â‰¥ 20, TCP offset â‰¥ 20, length checks. Reads
    seq/ack/flags (SYN/ACK/RST) and payload length. Then, under one lock:
    1. **TTL learning** (line 364): any inbound SYN-ACK from the peer IP (tracked or not) with no
       payload and not RST sets `peerTTLv = ip[8]` â€” once, since it only fills when still 0.
    2. **Outgoing SYN on a tracked key** (line 368): (re)learns the ISN from the wire; a different
       seq on a later SYN resets the learned SYN-ACK state (fresh handshake on the same tuple);
       marks `isnKnown = true`. Note: a conn is only tracked if `announce` ran first â€” the
       announce happens after dial, so on most dials this branch does *not* fire (the SYN is long
       gone); that is fine, the two paths below cover it.
    3. **Inbound SYN-ACK for a tracked conn** (line 376): remembers `synAckSeq`/`synAckAck`; and
       the NAT follow: if `isnKnown` and the SYN-ACK's ack differs from `synSeq+1`, a uniform NAT
       rewrite happened â†’ `synSeq = ackv - 1`, so the marker packet's base and its "below stream start"
       property hold **as the server sees it**. This is the seq-mode field failure from January
       2026 made survivable (uniform rewrites only; non-uniform normalization still defeats any
       client-side marker â€” RESEARCH-2 Â§1.1).
    4. **Fire conditions** (line 390):
       - early (`isnKnown`): any outbound ACK-carrying, non-SYN segment whose seq is at or after
         the stream start (`seq - synSeq + 1 < 0x80000000`, wrap-safe comparison) fires with
         `base = synSeq + 1` and `ack = the segment's ack` â€” the final handshake ACK normally, or
         the first data segment if the final ACK was never observed (the 2.6.0 missed-ACK case).
       - late (`!isnKnown`): the first outbound **data** segment (payload > 0, ACK, no SYN) fires
         with `base = its seq` â€” the segment's own sequence number IS the stream start. Bare ACKs
         never fire (pinned by `TestDesyncLateNeedsData`). Gating: needs either `synAckAck != 0`
         (a SYN-ACK was seen, so the marker can ack the server's SYN plausibly) or `isnKnown`
         (line 387).
  - `fireLocked(k, c, base, ack uint32)` (line 405) â€” mu held by caller. TTL selection: seq mode â†’
    64; ttl mode â†’ `cfg.TTL`, and when that is â‰¤ 0 (auto) â†’ `peerTTLv âˆ’ 1`, or, if the peer TTL
    was never learned, `miss++` + one log line and **no fire** (degrade: Wrap still gets released
    via abandon on timeout; the tunnel works unclassified). Then: `firedN++`, delete the conn and
    its wait entry, close the wait channel (releasing Wrap), and â€” exactly once per connection â€”
    `send(fakePacket(k, base âˆ’ len(hello), ack, ttl, hello))`.

**Removed from 2.6.0 (moved into the tracker):** `Desync`/`desyncInjector`/`desyncConn` state
machine and `fire()` (Linux file), the `handle()` method, the per-injector `announce` with fixed
`known` semantics.

### Rewritten â€” `wat/desync_linux.go` (Linux only, 176 lines)

- `desyncWrapTimeout = 2 * time.Second` (line 29) â€” how long Wrap waits for the marker.
- `tcpStreamBase(tc *net.TCPConn) (nxt uint32, ok bool)` (line 35) â€” NEW probe, the piece that
  makes the early path work after dial returns. Sequence: `tc.SyscallConn()` â†’ `Control` â†’
  `setsockopt(TCP_REPAIR, 1)` â†’ defer `setsockopt(TCP_REPAIR, 0)` â†’ `setsockopt(TCP_REPAIR_QUEUE,
  1 /* TCP_SEND_QUEUE */)` â†’ raw `Syscall6(SYS_GETSOCKOPT, fd, IPPROTO_TCP, TCP_QUEUE_SEQ, &b,
  &l=4)` (x/sys/unix has no TCP_QUEUE_SEQ wrapper; 4 bytes, little-endian read) â†’ `TCP_REPAIR` off
  via the defer. Returns the send-queue sequence number (SND.NXT = stream start right after the
  handshake). `ok=false` on any failure â€” the probe needs **CAP_NET_ADMIN** (CAP_NET_RAW alone is
  not enough for TCP_REPAIR); the caller then uses the late path. Non-invasive: repair mode only
  freezes queue accounting; buffers untouched; the socket keeps working.
- `Desync` struct `{inj *desyncInjector}` (line 67) â€” same public shape as 2.6.0.
- `NewDesync(cfg DesyncConfig, peer string) (*Desync, error)` (line 72): `validateDesync` first
  (identical error messages on every OS), then `desyncPeerHostPort` + `net.ParseIP` â€” requires an
  IPv4 peer (`wat: desync needs an IPv4 -peer`), then `newDesyncInjector`.
- `Wrap(c net.Conn) (net.Conn, error)` (line 93): non-TCPConn passes through; non-IPv4 addrs pass
  through; otherwise builds the outgoing `desyncKey`, probes `tcpStreamBase`, `announce`s with
  `(isn, known)`, then `select` on the wait channel vs `time.After(desyncWrapTimeout)`; on timeout
  `abandon(k)`. Always returns the original conn â€” timeout degrades to unclassified, never to a
  broken tunnel.
- `Close()` (line 118) â€” `sync.Once`-guarded: `tr.close()` then `unix.Close(fd)`.
- `desyncInjector` (line 123) â€” now a thin shell: `{tr *desyncTracker, fd int, closed sync.Once}`.
- `newDesyncInjector(cfg, peerIP [4]byte)` (line 130): one `AF_PACKET`/`SOCK_RAW|SOCK_NONBLOCK`
  socket on `ETH_P_ALL` (error wrapped: `wat: -fake-sni needs CAP_NET_RAW: %w`), tracker built,
  `tr.send = d.sendRaw` (the injection seam), reader goroutine started.
- `loop()` (line 149): nonblocking `unix.Read` into a 2048-byte buffer; EAGAIN/EINTR continue;
  anything else â†’ 10 ms backoff (Wrap's timeout governs); successful reads go through
  `parseEthIPv4` â†’ `tr.handleIPv4`.
- `sendRaw(pkt []byte)` (line 168): unchanged from 2.6.0 â€” one throwaway `IPPROTO_RAW` socket
  (IP_HDRINCL; the kernel fills the IP checksum) per fire, `Sendto` with the packet's own dst.

### Rewritten â€” `wat/desync_other.go` (`!linux`, 22 lines)

- `NewDesync` runs `validateDesync(cfg)` FIRST â€” a bad mode/SNI/TTL fails identically off-Linux â€”
  and only then returns the platform error `wat: -fake-sni needs Linux with CAP_NET_RAW (the ICMP
  carrier's requirement)`. `Desync` struct + `Wrap`/`Close` no-op stubs unchanged (they only exist
  so `cmd/wattun` compiles).

### Rewritten â€” `wat/desync_test.go` (16 tests, 498 lines, all pass on Windows)

Test helpers (portable, so the whole state machine is tested off-Linux):
- `desyncTestPkt(...)` (line 156) â€” builds one raw IPv4+TCP packet exactly as the wire delivers it
  (checksum in place), so `handleIPv4` sees realistic input.
- flag consts `testFlagFIN/RST/PSH/ACK/SYN` (line 177).
- `desyncTestTracker(mode string, ttl int)` (line 186) â€” tracker with SNI `mci.ir` and a
  collecting `send` (`sent *[][]byte`); peer IP 10.8.0.1.
- `testClientKey()` (line 203) â€” the fixed test 4-tuple 192.168.1.2:5000 â†’ 10.8.0.1:443.
- `feedFullHandshake(tr, k, isn, srvSeq)` (line 211) â€” drives SYN (client) â†’ SYN-ACK (server, TTL
  52) â†’ final ACK into the tracker.

Kept from 2.6.0 (unchanged): `TestFakeClientHelloRealParser` (feeds the marker packet to a stdlib
`crypto/tls` TLS 1.2 server; pass = record+hello parse cleanly and the handshake advances â€”
net.Error / AlertError / EOF / ErrClosedPipe accepted, parse rejection fails),
`TestFakeClientHello` (SNI round-trip Ã—3 names, record length consistency, per-build randomness,
empty SNI â†’ nil), `TestDesyncSeqBefore` (seq arithmetic pin), `TestDesyncPeerIP`,
`TestTCPChecksum` (folded-sum self-consistency).

New (each pins one mechanic of the tracker):
1. `TestValidateDesync` â€” seq ok, ttl ok, ttl+TTL 0 ok (auto), empty SNI fails, bad mode fails,
   TTL 300 fails.
2. `TestDesyncEarlyFiresBeforeData` â€” announce(isn+1, known) â†’ full handshake â†’ exactly one marker;
   pins: packet length (40+len(hello)), seq = isn+1âˆ’len(hello), ack = server ISN+1, TTL 64 in seq
   mode, ports of the 4-tuple, `fired()` == 1.
3. `TestDesyncEarlyFiresOnFirstData` â€” wrap-prone ISN 0xffff0000; first data segment arrives
   before any final ACK was seen â†’ marker still fires with base = stream start (the 2.6.0 killer
   case).
4. `TestDesyncLateFiresOnData` â€” announce(0, known=false), sniffer missed the SYN; SYN-ACK + first
   data â†’ fires anchored to the data segment's seq.
5. `TestDesyncLateNeedsData` â€” late mode: SYN-ACK + two bare ACKs â†’ **no** fire.
6. `TestDesyncNATRewrite` â€” SYN with ISN 1000, SYN-ACK acking 2001 (NAT rewrote to ISN 2000) â†’
   marker seq = 2000+1âˆ’len(hello): the marker follows the NAT-shifted base as the server sees it.
7. `TestDesyncTTLCalibration` â€” ttl mode, TTL 0; SYN-ACK arrives with IP TTL 52 â†’ marker goes out
   with TTL 51 (one hop short of the server).
8. `TestDesyncTTLCalibratedBeforeHandshake` â€” a stray SYN-ACK from the peer on another port
   pre-learns TTL 60 â†’ subsequent handshake fires with TTL 59 immediately.
9. `TestDesyncTTLCalibratedNotYet` â€” ttl auto, no SYN-ACK seen â†’ no fire; `abandon` releases the
   waiting Wrap channel.
10. `TestDesyncFixedTTL` â€” ttl mode, TTL 9 â†’ marker TTL 9 (explicit value used as-is).
11. `TestDesyncOneMarkerPerConn` â€” post-fire segments (data, ACKs) never fire again.
12. `TestDesyncUnknownConnIgnored` â€” a full handshake on a never-announced tuple â†’ no fire.
13. `TestDesyncFakePacketRoundTrip` â€” built marker parses via `parseEthIPv4` (dst IP, TTL byte),
    TCP checksum recomputes to the stored value (zero â†’ compare â†’ restore), payload identity with
    `FakeClientHello("mci.ir")`.
14. `TestDesyncAbandonAndClose` â€” abandon closes the wait channel at once; after `close()`,
    announce returns a closed channel and nothing fires.
15. `TestDesyncParseEthIPv4` â€” ARP frame and short frame rejected.

### Modified â€” `cmd/wattun/main.go` (3 hunks)

- `attachFakeSNI` (line 204, closure inside `main()` because it reads the flag locals): unchanged
  logic â€” builds one `wat.Desync` per peer and installs it as the pool's dial hook (`SetDialHook`)
  â€” but its comment now says the carrier scope; and it is now called in one more place:
  - line 268: `tcp` carrier client case (2.6.0 behavior kept);
  - line 287: `tls` carrier client case (2.6.0 behavior kept);
  - line 328: NEW â€” after the `ws|wss|h2|h2c|grpc` client switch builds its pool client
    (`NewWSPoolClient`/`NewGRPCPoolClient`/`NewH2PoolClient`), `attachFakeSNI(pc, peer)` runs on
    success. All five dial through `TCPPoolClient` slots, so the dial hook covers every
    connection including lazy redials. (`h2c` rides along but is pointless there â€” a cleartext h2
    flow has no TLS shape for the marker packet to imitate.)
- Flag help text (lines 85-87): `-fake-sni` now lists `tcp|tls|wss|h2|grpc` and says the sniffer
  tracks outgoing handshakes on the wire; `-fake-mode` ttl says `needs -fake-ttl N or 0 =
  calibrate it once with traceroute before the first marker` â€” corrected to reflect that 0 means
  auto-calibration from the peer's SYN-ACKs; `-fake-ttl` help ends with `0 = calibrate once from
  the server's replies`.
- No config.go change: config keys derive from flags via `flag.Lookup` (project convention).

### Docs + version

- `docs/TECHNICAL.md`:
  - "Fake-SNI desync (`fake-sni`, 2.6.0)" section (Carriers chapter): added the 2.7.0 paragraph â€”
    wire-watch trigger anchored to final ACK or first data segment, NAT-follow, carriers
    `tcp`/`tls`/`wss`/`h2`/`grpc`, `fake-ttl: 0` auto-calibration.
  - "Fake-SNI desync (whitelisting survival)" section: carrier list extended, `fake-mode: seq`
    bullet now says a uniform NAT rewrite shifts the marker packet with it (2.7.0), `fake-mode: ttl` bullet
    documents `fake-ttl: 0` auto.
  - Flag/config table: the three desync flag rows existed TWICE (2.6.0 doc bug) â€” collapsed to one set;
    `fake-ttl` row documents 0 = auto since 2.7.0.
  - Release history: new `2.7.0` entry (trigger fix explained in user terms, NAT follow, auto-TTL,
    carrier scope, client-only/server-unchanged/no wire change) above the 2.6.0 entry.
- `README.md`: badge â†’ `release-v2.7.0`; intro sentence names the 2.7.0 scope (wss/h2/grpc +
  auto-TTL + NAT follow).
- `README.fa.md`: same two changes; Farsi prose inside `<div dir="rtl">`, Persian digits
  (Û²Ù«Û·Ù«Û°), written natively (not translated).
- `wat/version.go`: `Version = "2.7.0"`.

---

## Compatibility and performance invariants

- **Wire compatibility: unchanged.** the marker packet is a raw packet injected next to the flow; server,
  session, frames, crypto untouched. No new frame types. Old server + new client and vice versa
  work. (The `h2c` carrier accepts the flag but gains nothing â€” cleartext flow.)
- **ICMP path: untouched.** No diff in `session.go`, `cc.go`, `sched.go`, `fec.go`,
  `icmp_linux.go`, `carrier_tcp.go`, `carrier_udp.go` â€” the sim tests' pins are not at risk from
  this round's diffs.
- **Non-Linux:** compiles; `-fake-sni` fails at startup with the same platform error as 2.6.0
  (after running the shared config validation first, so a bad `-fake-mode` errors identically
  everywhere).

## Verification status (this Windows box)

- `go build ./...` âœ… Â· `go vet ./...` âœ… Â· `GOOS=linux go build ./...` âœ…
- `go test -count=1 ./cmd/...` â€” 29 pass âœ…
- Desync tests 16/16 âœ…:
  `go test -count=1 -run 'TestDesync|TestFake|TestValidateDesync|TestTCPChecksum' ./wat/`
- `go test -count=1 -run 'TestTwoClientsSameKey|TestFairQueueUngroupedIsPerStream' ./wat/` â€” pass
  (the two tests the 2.6.0 handoff saw time out under load; healthy alone here).
- `GOOS=linux go test` cannot *execute* on Windows (linux/amd64 test binary) â€” build-only check.
- **Environment notes for the next agent on this Windows box:**
  - The pwsh tool runs at Low integrity: it cannot write `%LOCALAPPDATA%\go-build`, the Go module
    cache, or `.git/index.lock`. Go needs workspace-local caches:
    ```powershell
    $env:GOCACHE="$PWD\.gocache"; $env:GOMODCACHE="$PWD\.gomodcache"; $env:GOPATH="$PWD\.gopath"
    ```
  - `git commit`/`git add` from the sandboxed shell fail with `index.lock: Permission denied` â€”
    the commit was made via one sandbox-approved unconfined run; expect the same and escalate
    once if you commit.
  - `.gocache/ .gomodcache/ .gopath/ .acl-recovery/` are untracked artifacts of that setup; safe
    to delete or `.gitignore`.
- Full `wat/` suite: NOT run to completion (known ~5 min + this box's load flakiness â€” times out
  on clean `main` too; same caveat as the 2.6.0 handoff). Re-run with `-timeout 600s` on a quiet
  Linux box; nothing this round touches session/cc/ICMP.
- Linux raw-socket behavior (`tcpStreamBase` probe under real CAP_NET_ADMIN, real AF_PACKET
  sniffing, `sendRaw`) not exercised on Windows â€” needs a Linux host with CAP_NET_RAW
  (+ CAP_NET_ADMIN for the probe). Untested-on-hardware, flagged.

## Not done / next steps for another agent

1. **Field-validate on an Iran path** (the queue, in order): does the early path fire on tcp and
   tls carriers (marker visible at the filter); does `fake-ttl: 0` calibrate; does the NAT-follow
   rescue an ISP where 2.6.0/seq died.
2. If fake-SNI gets blocked while TCP still passes: RESEARCH-2 Â§1.2 â€” real-ClientHello disorder.
   **2.7.1 note: this is an NFQUEUE architecture change, not a function** (zapret's disorder needs
   to hold the real segment back before the kernel sends it; our AF_PACKET observer cannot). Do not
   bolt it on; decide deliberately.
3. ~~Restricted-routing scenario: write the domestic-relay chain recipe into TECHNICAL.md~~ â€” **done in
   2.7.1** (see below).
4. Push `dev`, tag `v2.7.0`/`v2.7.1` â†’ release workflow; after it finishes
   `gh release edit vX.Y.Z --notes-file <file>`. Client-only update; server unchanged; no wire
   change; mixed versions fine.
5. ~~Teach `wattun-manager` the fake-sni flags~~ â€” **done in 2.7.1** (see below).
6. ~~`.gitignore` for build artifacts~~ â€” **done in 2.7.1**.
7. Optional (flagged): IPv6 in the injector â€” still IPv4-only by design, same as the reference
   tool; add only if a real deployment needs it.
8. **Refinement mission for the next agent (owner request):** read all the `.md` files on this
   branch first — `FAKE-SNI-DESIGN.md`, `AGENT-HANDOFF-CHANGES.md`, `AGENT-HANDOFF-CHANGES-2.md`
   (this file), `RESEARCH-2.md`, `RESEARCH-3.md`, plus `docs/TECHNICAL.md` — then fully refine
   EVERYTHING that was added in this branch (2.6.0 + 2.7.0 + 2.7.1: the fake-SNI feature end to
   end, its three modes, the probe, the tracker, the manager screens, the docs), and rethink how
   all of it is presented and managed in `wattun-manager` (one coherent UX for name/mode/ttl
   across the Iran wizard, the advanced menu, and the unattended flags). Only after that
   re-think, consider the new items from `RESEARCH-3.md` section 2 (connection churn first, then
   the optional marker IP-fragmentation knob; the larger Bale/WebRTC carrier only on field
   evidence that the current paths died). Keep every rule in CLAUDE.md: wire compatibility,
   client-only where stated, docs in sync, ICMP path untouched.

---

# 2.7.1 â€” what `27ccdf3` changed, in full detail

Round-2 work: the round-1 handoff's queue, researched and implemented. Commit `27ccdf3`
(JohnWatsoon only), 11 files +301/âˆ’30. Server unchanged, wire unchanged, ICMP path untouched.

## Research that drove it (re-cloned sources still in %TEMP%\wt-research)

- **GoodbyeDPI `--wrong-chksum`** (`src/fakepackets.c`, `send_fake_data`, lines ~145-215): the marker packet
  is a copy of the triggering data packet with its payload replaced by the marker hello, checksums
  recomputed via `WinDivertHelperCalcChecksums`, then **damaged**: `ppTcpHdr->Checksum =
  htons(ntohs(ppTcpHdr->Checksum) - 1)`. The seq variant (`--wrong-seq`) moves AckNum by âˆ’66000 and
  SeqNum by âˆ’10000 (comment: 66000 is the smallest drift Linux â‰¥ 2.6.18 still tolerates in
  `nf_conntrack_proto_tcp.c` â€” window accounting). README line 100: wrong-seq + wrong-chksum send
  two distinct markers.
- **zapret `--dpi-desync-variant badsum`** (`nfq/darkmagic.c:267`): `tcp->th_sum ^= 1 +
  random()%0xFFFF` AFTER `tcp4_fix_checksum` â€” same idea, random damage instead of âˆ’1. Also
  `FOOL_BADSEQ` (darkmagic.c:132): seq/ack shifted by configurable increments (defaults âˆ’10000 /
  âˆ’66000, desync.c `badseq_increment`/`badseq_ack_increment`).
- **zapret's marker-variant caveats** (`docs/readme.en.md:279-289`, authoritative field wisdom): badsum
  "doesn't work if your device is behind a NAT which does not pass invalid packets" (Linux
  `nf_conntrack_checksum=1` + INVALID-drop FORWARD rule kills it; openwrt sets it to 0; ISPs
  usually pass badsum); **badseq** markers are dropped by the server "but DPI also can ignore them" â€”
  i.e. badseq is the weaker variant. This directly ranked badsum above badseq for the new mode.
- **Disorder verdict corrected** (Â§1.2 of RESEARCH-2.md updated): zapret's multisplit/multidisorder
  run under NFQUEUE â€” the kernel hands nfqws the real packet, which holds/re-cuts/re-injects it.
  Our AF_PACKET observer is read-only; it can never hold back the real ClientHello. Disorder would
  need an NFQUEUE data path (iptables + root + per-packet verdicts) â€” an architecture change, so it
  stays LATER with that reason now written down.

## Fix: `Wrap` probe off-by-one (`wat/desync_linux.go`)

`tcpStreamBase` returns SND.NXT â€” the next unsent sequence number, which is ISN+1 right after the
handshake completes â€” but `Wrap` announced it as the ISN, so the tracker's `synSeq` was one too
high: the early-path marker would have sat at ISN+2âˆ’len instead of ISN+1âˆ’len, i.e. **in-window**
(one byte above the stream start) â†’ the server would have accepted the marker packet's first bytes as real
data and corrupted the stream. Worst-case failure, found only by auditing the kernel accounting.
Fix in `Wrap` (desync_linux.go, Wrap body):

```go
isn, known := tcpStreamBase(tc)
if known {
    isn--
}
ch := d.inj.tr.announce(k, isn, known)
```

Pinned by `TestDesyncProbeIsnArithmetic` (below). Note the asymmetry with NAT-follow: the tracker's
handleIPv4 learns the ISN from the SYN on the wire (correct as-is), and rebuilds it from a SYN-ACK
ack as `ackv âˆ’ 1` (also correct); only the probe path needed the âˆ’1.

## New: `fake-mode sum` (`wat/desync.go`)

The third variant (GoodbyeDPI `--wrong-chksum` / zapret badsum), for filters that validate TCP
sequence numbers â€” where `seq`'s below-window marker is read as junk and ignored. The marker mirrors
the first outbound **data segment**: identical seq (in-window, so a strict filter reassembles it
as the flow's first flight), identical ack, valid TTL â€” but a damaged TCP checksum, which every
server kernel rejects at checksum validation, keeping the flow clean by construction.

- `DesyncConfig.Mode` doc now lists `"seq" | "ttl" | "sum"`; `validateDesync` accepts `sum`.
- `desyncTracker` gained `sumSeq uint32` â€” the seq of the data segment being mirrored, captured in
  `handleIPv4` (both trigger paths set it: early waits for a segment with payload>0 â€” bare ACKs
  have nothing to mirror â€” then `t.sumSeq = seq`; late is already data-anchored so it sets it too).
- `fireLocked` in sum mode: `base = t.sumSeq` before the below-window arithmetic, then the packet
  goes out with the **checksum damaged**: after `fakePacket` computes the correct checksum, the
  field is rewritten `(s ^ 1) - 1` (GoodbyeDPI's âˆ’1, plus a bit-flip so no off-by-one coincidence
  can repair it). TTL selection (64 / fixed / auto) unchanged â€” sum uses the same defaults as seq.
- The firing rules per mode, final form (all in `handleIPv4`):
  - early + seq/ttl: fires on the final ACK **or** first data, `base = synSeq + 1`.
  - early + sum: waits for the first data segment, `base = synSeq + 1` but the marker packet's seq is
    `sumSeq âˆ’ len(hello)` (in-window mirror).
  - late + any: first data segment, `base = seq`.

## New tests (`wat/desync_test.go`, now 19)

- `desyncTestTracker` gained the `"sum"` case.
- `TestDesyncProbeIsnArithmetic` â€” pins the Wrap conversion: announce with `sndNxt âˆ’ 1` (= ISN),
  fire must land at `ISN+1âˆ’len(hello)` exactly as with a wire-learned ISN.
- `TestDesyncSumModeFiresOnData` â€” sum mode: bare final ACK does NOT fire; first data segment
  fires; pins marker seq = `ISN+1âˆ’len(hello)`, ack = server ISN+1, checksum INVALID (recomputed
  good checksum â‰  stored), damage non-zero (`(good^1)âˆ’1` form).
- `TestDesyncSumModeLate` â€” late path + sum mode: SYN-ACK + first data â†’ fires with the mirrored
  base; pins the seq.

## `cmd/wattun/main.go` â€” flag help only

`-fake-mode` help now lists `sum` with its one-line contract ("valid window, bad TCP checksum â€¦
fails behind NATs that validate checksums"); `-fake-ttl` help ends "unused by the seq and sum
modes". No wiring changes (sum rides the same `attachFakeSNI` hooks).

## `wattun-manager` â€” fake-sni support (was: "optional, not done")

- Validators (near `v_fec`): `v_fake_mode` (seq|ttl|sum), `v_fake_ttl` (empty or 1-255),
  `v_sni_name` (allowlist-style name).
- `bin_ver_ok MIN` helper next to `ver_ge`: 1 when the installed wattun â‰¥ MIN (version gate for
  the 2.7.0 features).
- Iran wizard (`wizard_iran`): advanced block offers the fake-sni option on pool carriers when not reverse and
  running on Linux; asks name (empty = off), mode (default seq), ttl only for ttl mode (empty =
  auto). Emits `fake-sni:` (+ `fake-mode:` when â‰  seq, + `fake-ttl:` for ttl mode) via
  `write_client`; summary line "fake-sni name (mode)". Guards: `bin_ver_ok 2.7.0`.
- Advanced settings (`adv_menu`): new `k` entry for Iran + pool carrier + Linux â€” shows current
  fake-sni, asks the same triple, `set_value`/`sed -i` writes the keys, empty name strips all three
  (`sed -E '/^(fake-sni|fake-mode|fake-ttl):/d'`), auto-restart via the existing `changed` mechanism.
- Unattended: `--fake-sni NAME --fake-mode seq|ttl|sum --fake-ttl 0-255` parsed into `NI_*` and
  consumed by the wizard's asks; `usage()` documents them on the `iran` line. `MGR_VERSION`
  unchanged (manager changes ship from `main` without a tag).

## Docs + version (2.7.1)

- `docs/TECHNICAL.md`: Fake-SNI chapter â€” new `fake-mode: sum` bullet (mechanism, when it wins,
  NAT caveat, the `(checksum ^ 1) - 1` detail); flag table `fake-sni`/`fake-mode`/`fake-ttl` rows
  updated; **new "Full restricted-routing: the domestic relay chain (no new code)" subsection** (the Â§2.2
  promise kept: two-hop chain of stock wattun instances â€” relay-out client â†’ Kharej, relay-in
  server â†’ users, `WAT_PREFIX` sandbox note, relay-bandwidth caveat, fallback advice); new
  **2.7.1 release-history entry** above 2.7.0's.
- `README.md` / `README.fa.md`: badge â†’ `release-v2.7.1`; intro extended with the checksum mode
  (FA: Â«Ø­Ø§Ù„Øª Â«Ø³Ø§Ù…ÙÂ» Ø¨Ø§ Ø¬Ù…Ø¹â€ŒØ¢Ø²Ù…Ø§ÛŒÛŒ Ø®Ø±Ø§Ø¨Â», Persian digits Û²Ù«Û·Ù«Û±).
- `RESEARCH-2.md`: title/status updated; Â§1.2 disorder entry gains the NFQUEUE-architecture note;
  decision table gains row 1.1b (sum, BUILD 2.7.1); new Â§4b "What 2.7.1 changed, in one page";
  Â§5 queue rewritten (field validation first, disorder decision, release).
- `.gitignore`: added `AGENTS.md`, `.gocache/`, `.gomodcache/`, `.gopath/`, `.acl-recovery/`.
- `wat/version.go`: `Version = "2.7.1"`.

## Verification (2.7.1, this Windows box)

- `go build ./...` âœ… Â· `go vet ./...` âœ… Â· `GOOS=linux go build ./...` âœ…
- `go test -count=1 ./cmd/...` 29 pass âœ…
- Desync suite 19/19 âœ… (`-run 'TestDesync|TestFake|TestValidateDesync|TestTCPChecksum'`)
- `TestTwoClientsSameKey|TestFairQueueUngroupedIsPerStream` âœ… (the flaky pair, healthy)
- `bash -n wattun-manager` âœ… (via Git-for-Windows bash; note the sandboxed shell cannot run bash
  here â€” "couldn't create signal pipe, Win32 error 5" â€” use one approved unconfined run)
- Full `wat/` suite still not run on this box (known load flakiness, unchanged caveat; nothing
  2.7.1 touches session/cc/ICMP hot paths). Raw-socket half still needs a Linux + CAP_NET_RAW
  (+ CAP_NET_ADMIN for the probe) box for field validation.
