# AGENT-HANDOFF — what changed on branch `dev` (2.6.0 → 2.8.1)

Consolidated handoff, replacing `AGENT-HANDOFF-CHANGES.md` (2.6.0),
`AGENT-HANDOFF-CHANGES-2.md` (2.7.0 + 2.7.1), `AGENT-HANDOFF-CHANGES-3.md` (2.8.0),
`AGENT-HANDOFF-CHANGES-4.md` (2.8.1) and `NEXT-AGENT-PROMPT.md` (the next-agent brief). The five
documents follow verbatim in that order — part 1 = 2.6.0, part 2 = 2.7.0 + 2.7.1, part 3 = 2.8.0,
part 4 = 2.8.1, part 5 = the mission/queue/environment brief. References like "handoff 2" or
"AGENT-HANDOFF-CHANGES-2.md" inside the text mean that part; "RESEARCH-2"/"RESEARCH-3" mean
`RESEARCH.md` parts 2/3 (same § numbering).

Branch state at the time of the merge: five feature commits on `dev` (`bf92665`, `d355a05`,
`27ccdf3`, `1001f04`, `cc8cc3c` + `7378fde`), all committed, none merged to `main`, none tagged, no
release cut. Server binary untouched since 2.5.0, no wire format change anywhere on the branch, ICMP
path untouched. `wat/version.go` = 2.8.1, `MGR_VERSION=2026102001`.

Companions: `CHANGES-SINCE-2.5.0.md` (every change since 2.5.0 with what/why/how-decided),
`RESEARCH.md` (the design reference plus the method research and verdicts). Read `CLAUDE.md` and
`AGENTS.md` first.

Authorship: every commit, push, tag and release goes out under
`JohnWatsoon <133103370+JohnWatsoon@users.noreply.github.com>`; never add an AI name, trailer or
attribution line.

---

# Agent handoff: what changed on branch `dev` (2.6.0)

Commit `bf92665` on branch `dev` â€” 11 files, +695/âˆ’20. Not merged to `main`, not tagged, no release
cut. Everything below is committed; this file and `RESEARCH.md` are uncommitted by request.

## Why

The owner asked for availability-under-restriction capability: research tunnel projects that kept working through the
Iran whitelisting regime and bring the proven methods into WatTunnel. Reference project studied:
[patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) (wrong-seq extra ClientHello).
Field context: net4people/bbs issue #626 (January 2026 whitelisting, ~4 days of the method working,
defeated by ISP NAT sequence normalization in some networks).

## Files changed (committed)

### New â€” `wat/desync.go` (portable, builds everywhere)
- `FakeClientHello(sni string) []byte` â€” builds a minimal, RFC-compliant TLS 1.2 ClientHello carrying an
  arbitrary SNI. Record header `16 03 01`, handshake type 1, client version `03 03`, 32 random bytes
  (`crypto/rand`, so no fixed fingerprint), empty session id, cipher suites `0xc02b, 0xc023`
  (ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES128-SHA256), null compression, three extensions:
  server_name (0000), supported_groups (000a: x25519, secp256r1), signature_algorithms (000d:
  ecdsa_secp256r1_sha256). Returns `nil` for empty SNI.
- `parseSNIOf(rec []byte) (string, error)` â€” test-only parser of our own hello; asserts round-trip.
- `DesyncConfig{SNI, Mode, TTL}` â€” mode `seq` (default) or `ttl`.
- `csum`, `tcpChecksum` â€” moved here from `icmp_linux.go` so tests compile on all OSes.
  `icmp_linux.go` now has a one-line comment pointing here. `htons` also lives here.

### New â€” `wat/desync_linux.go` (Linux only)
- `Desync` type + `NewDesync(cfg, peer)` â€” validates config, resolves the peer to IPv4, opens one
  AF_PACKET `SOCK_RAW|SOCK_NONBLOCK` sniffer on `ETH_P_ALL`, spawns `loop()`.
- `Wrap(c net.Conn) (net.Conn, error)` â€” called by the pool after dial. Announces the connection's
  outgoing 4-tuple to the sniffer, waits â‰¤ 2 s for the marker packet to be sent, returns the conn
  unchanged. Non-IPv4-TCP conns pass straight through; a handshake the sniffer never sees (offload
  paths) falls through after the timeout â€” tunnel still works, just unclassified.
- `desyncInjector` state machine (`handle()`): outgoing SYN â†’ record ISN; inbound SYN-ACK â†’ record
  `synAckSeq` and `synAckAck`; outgoing final ACK (ack field == `synAckSeq+1`) â†’ mark done, release
  the waiting `Wrap`, spawn `fire()`. Keys are the outgoing 4-tuple; inbound frames match the
  reversed key.
- `fire()` â€” builds IPv4(20) + TCP(20) + hello packet: `seq = synSeq + 1 âˆ’ len(hello)` (fully below
  the stream start), ack = `synAckAck`, flags PSH|ACK (0x18), window 0xffff, DF bit, TTL 64 (seq
  mode) or `cfg.TTL` (ttl mode), valid TCP checksum. Sent through a throwaway IPPROTO_RAW socket
  (IP_HDRINCL) via `Sendto`.

### New â€” `wat/desync_other.go` (`!linux`)
- `NewDesync` returns an error at startup ("needs Linux with CAP_NET_RAW"); no-op `Desync` so callers compile.

### New â€” `wat/desync_test.go` (5 tests, all pass on Windows)
- `TestFakeClientHelloRealParser` â€” feeds the hello to `crypto/tls.Server` (TLS 1.2 pinned, self-signed
  cert). Acceptance: net.Error / AlertError / EOF / ErrClosedPipe, i.e. the record parsed and the
  handshake advanced past parsing (the hello never completes key exchange). A parse-level rejection
  fails the test.
- `TestFakeClientHello` â€” SNI round-trip, record length consistency, randomness between builds, empty SNI â†’ nil.
- `TestDesyncSeqBefore` â€” pins the seq arithmetic.
- `TestDesyncPeerIP` â€” host:port and hostname; no assertion on unresolvable hosts (wildcard resolvers).
- `TestTCPChecksum` â€” self-consistency (folded sum 0xffff with checksum in place).

### Modified â€” `wat/carrier_tcp.go`
- `TCPPoolClient` gained a dial hook:
  ```go
  SetDialHook(hook func(ctx, slot int, inner func(ctx, int) (net.Conn, error)) (net.Conn, error)) error-free
  ```
  stored in an `atomic.Pointer`; `dialer()` wraps `c.dial` when a hook is set; `slotLoop` now calls
  `c.dialer()`. No behaviour change when no hook is set (default path byte-identical).

### Modified â€” `cmd/wattun/main.go`
- Three new client flags: `-fake-sni` (empty = off), `-fake-mode` (`seq`|`ttl`, default `seq`),
  `-fake-ttl` (required > 0 for ttl mode).
- `attachFakeSNI` closure inside `main()` (must stay inside: it reads the flag locals): builds one
  `wat.Desync` per peer and installs it as the pool's dial hook so every connection passes through
  `Wrap`. Wired into the `tcp` and `tls` client cases only.

### Modified â€” `wat/icmp_linux.go`, `wat/version.go`
- csum moved out (comment left behind); Version â†’ `2.6.0`.

### Docs â€” `docs/TECHNICAL.md`, `README.md`, `README.fa.md`
- TECHNICAL: three flag rows (Since 2.6.0), new "Fake-SNI desync" subsection under Carriers with the
  NAT-normalization caveat, troubleshooting row "Connects, then stalls on tcp/tls with `fake-sni`",
  2.6.0 release-history entry (client-only, server unchanged, no wire change).
- Both READMEs: badge â†’ `release-v2.6.0`, intro sentence names fake-SNI desync. Farsi prose in
  `<div dir="rtl">` with Persian digits (Û²Ù«Û¶Ù«Û°).

## Verification status

- `GOOS=linux go build ./...` âœ… Â· `go build ./...` âœ… Â· `go vet ./...` âœ…
- `go test -count=1 ./cmd/...` â€” 29 pass âœ…
- Desync tests: 5/5 on Windows âœ…
- `bash -n install.sh wattun-manager` âœ…
- Full `wat/` suite: times out at 280 s **on clean main too** (baseline hangs on
  `TestTwoClientsSameKey`, my run on `TestFairQueueUngroupedIsPerStream`; both pass alone). Machine
  load flakiness on this Windows box, not a regression. Re-run with `-timeout 600s` on a quiet machine
  if you want belt and braces.
- Linux raw-socket path (`desyncInjector`) not exercised by tests and cannot be tested on Windows â€”
  needs a Linux box with CAP_NET_RAW. Untested code, flagged as such.

## Not done / next steps for another agent

- Push `dev`, tag `v2.6.0` â†’ release workflow. Tag push runs `go test ./...` + `build.sh`; after it
  finishes, `gh release edit v2.6.0 --notes-file <file>` (client-only update, both ends SHOULD update
  but the server binary is functionally unchanged; no wire change).
- Optional: teach `wattun-manager` the new flags (config keys already work â€” they derive from flags).
- Optional: IPv6 support in the injector (currently IPv4 only, by design â€” the tool it is modelled on is IPv4 too).
- Commit these two handoff files if wanted.

---

# Agent handoff: what changed on branch `dev` (2.7.0 + 2.7.1)

Branch `dev` now carries TWO commits on top of `bf92665` (2.6.0):

- `d355a05` â€” **2.7.0** "fake-sni desync hardened and fixed: the marker now actually fires" (13 files,
  +1490/âˆ’209), with `RESEARCH.md` (method research for the whitelisting and Restricted-routing scenarios)
  and `RESEARCH.md` (2.6.0 design; packet layout and marker-hello mechanics unchanged, only the
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
   branch first — `RESEARCH.md`, `AGENT-HANDOFF.md`, `AGENT-HANDOFF.md`
   (this file), `RESEARCH.md`, `RESEARCH.md`, plus `docs/TECHNICAL.md` — then fully refine
   EVERYTHING that was added in this branch (2.6.0 + 2.7.0 + 2.7.1: the fake-SNI feature end to
   end, its three modes, the probe, the tracker, the manager screens, the docs), and rethink how
   all of it is presented and managed in `wattun-manager` (one coherent UX for name/mode/ttl
   across the Iran wizard, the advanced menu, and the unattended flags). Only after that
   re-think, consider the new items from `RESEARCH.md` section 2 (connection churn first, then
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
- **Disorder verdict corrected** (Â§1.2 of RESEARCH.md updated): zapret's multisplit/multidisorder
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
- `RESEARCH.md`: title/status updated; Â§1.2 disorder entry gains the NFQUEUE-architecture note;
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

---

# Agent handoff: what changed on branch `dev` (2.8.0)

Branch `dev` now carries 2.8.0 on top of 2.7.1 (`ce058b3` docs / `67b3842` research / `a9784c3`
wording pass). **Commit pending at the time of writing — this file is committed together with the
2.8.0 changes.** Server unchanged, wire unchanged, ICMP path untouched. Everything below is the
full per-symbol map, continuing the format of AGENT-HANDOFF.md (rounds 1–2). The
research that drove this round is RESEARCH.md; its §2 items 1 and 3 are now implemented.

## Why (the owner request)

The owner asked for the round-3 suggestions to be implemented. Two of the ranked ideas were
client-only, wire-compatible and testable on the Windows box, so they shipped now:

1. **Connection churn** (`pool-rotate`) — item 1 of RESEARCH-3 §2, the best speed-per-effort item:
   no pool connection should present a months-stable lifetime × volume profile to a behavioral
   classifier (#649: "a TLS flow held open for hours moving tens of GB is anomalous regardless of
   a perfect handshake"; #628: throughput → probe → block domain+IP).
2. **`fake-mode: seqsum`** — the double-marker experiment (§3): both the seq and the sum marker
   per connection, so a filter must discard both correctly to miss the SNI.
3. **A real bug found on the way (the headline): the 2.7.1 sum-mode checksum damage was an
   identity for every even checksum.** `(s ^ 1) - 1` with s even = `(s+1) - 1 = s`. Half of the
   sum-mode markers shipped with a fully VALID checksum; the server would have accepted the fake
   hello's bytes as real stream data (flow corruption, the worst failure class). Found because the
   sum-mode unit test flaked at ~50 % — the fake hello's crypto/rand bytes decide the checksum's
   parity. Fixed in `damageChecksum`.

## Files changed, in full detail

### Modified — `wat/desync.go`

- `DesyncConfig.Mode` doc: adds `"seqsum"`.
- `validateDesync`: accepts `seqsum` (error text: `-fake-mode must be seq, ttl, sum or seqsum`).
- `handleIPv4` trigger paths: both the early and the late branch now treat `"sum" || "seqsum"` as
  the mirroring modes (wait for the first outbound DATA segment, capture `t.sumSeq = seq`; bare
  ACKs do not fire). Unchanged for `seq`/`ttl`.
- `fireLocked`:
  - `sumMode := t.cfg.Mode == "sum" || t.cfg.Mode == "seqsum"` picks `base = t.sumSeq`.
  - New `seqsum` branch sends TWO packets: `fakePacket(k, base-len(hello), ack, ttl, hello)` (the
    plain below-window seq marker, valid checksum) and then `fakePacket(k, base, ack, ttl, hello)`
    with `damageChecksum` applied (the in-window mirror). Both leave before the server in the seq
    sense (below-window / bad checksum); the ordering matters — the below-window one first, so a
    window-checking reassembler sees junk first and a checksum-checking one drops the second.
  - The old inline sum damage is replaced by `damageChecksum(pkt)`.
- **New `damageChecksum(pkt []byte)`**: `d = s - 1`, and when that wraps to `0xffff` (the valid
  fold of a correct packet is exactly `0xffff`, so `-1` from `0x0000` would be VALID) it writes
  `s - 2` instead. Always invalid, for every input, no parity dependence. Doc comment carries the
  full 2.7.1 post-mortem so nobody reintroduces the `(s^1)-1` shape.

### Modified — `wat/carrier_tcp.go` (the churn engine)

- `TCPPoolClient` struct: two new atomics, `rotate` (ns duration base, 0 = off) and `rotBytes`
  (datagram-count base, 0 = off).
- `poolConn` struct: new `rot atomic.Pointer[rotateBudget]` — nil on the server side (churn is a
  client concept).
- New `rotateBudget{at time.Time; bytes int64}` — one connection's jittered budget; a fresh one is
  rolled for every (re)connection, so no two connections share a period.
- New `rollRotate(base, baseBytes)`: time jitter ±40 % (`0.6 + 0.8*jitter01()`), count jitter ±25 %
  (`0.75 + 0.5*jitter01()`); floors 10 s / 1 MB (a bad roll can never hot-loop the redialer).
- New `jitter01()`: uniform [0,1) from crypto/rand (spread, not secrecy).
- New `(pc *poolConn) rotateDue(now)`: true when either axis is hit (`now > at`, or `tx >= bytes`;
  tx counts pool datagrams handed to the socket — near-uniform size, already lock-free).
- New `SetRotate(d time.Duration, bytes int64)`: public knob; stores both bases. Client pools only.
- `slotLoop` (client side): after `newPoolConn`, when either base is non-zero it stores
  `rollRotate(...)` on the connection.
- Health check (the `case now := <-t.C` branch): before the slow-connection judgement, when churn
  is on, any slot whose `rotateDue` is true gets `poolRotates.Add(1)` + `pc.fail()` — the existing
  death path (queue drained/dropped, session resends in flight, slot redials immediately). Runs
  BEFORE the `keepSlow` continue, so churn works on direct paths too.
- `Clone()` copies both rotate bases (sessions `-sessions > 1` keep the policy).
- New counter `poolRotates` + accessor `PoolRotates() int64` (next to `PoolSlowKills()`), for
  `/stats`-adjacent observation later.

### New — `wat/rotate_test.go` (2 tests, pass, no flake)

- `TestRollRotateJitterBounds` — 500 rolls of a 1 h base must land in 36..84 min; 4 MB base in
  3..5 MB; floors hold (1 s → ≥10 s, 1 → ≥1 MB); zero base → zero budget.
- `TestRotateDueSemantics` — no budget → never due; past `at` → due; inside `at` → not due;
  `tx >= bytes` → due; below → not due.

### Modified — `wat/desync_test.go` (21 tests now)

- `desyncTestTracker` knows `"seqsum"`.
- New `TestDesyncSeqSumSendsBoth` — early path: bare ACK does NOT fire; first data fires ONCE but
  sends TWO markers; marker 1 = below-window seq + VALID checksum (recomputed == stored); marker 2
  = in-window seq (`isn+1`) + INVALID checksum; both payloads equal `FakeClientHello("mci.ir")`.
- New `TestDesyncSeqSumLateFiresBoth` — late path (unknown ISN): SYN-ACK + first data → two
  markers, seqs `isn+1-len(hello)` and `isn+1`.

### Modified — `cmd/wattun/main.go`

- New client flag `-pool-rotate` (default `0`): Go duration (`30m`, `4h`, `90s`); parsed next to
  the other validations, `0` = off; negative or unparsable → fatal with usage. Wired in `build()`:
  `pc.SetRotate(rotateD, 0)` for every client pool (tcp/tls/ws/wss/h2/grpc — all flow through the
  single `pc != nil` block), gated on `!server`.
- `-fake-mode` help lists `seqsum`.
- Config key `pool-rotate` derives from the flag automatically (project convention).

### Modified — `wat/version.go`, `docs/TECHNICAL.md`, `README.md`, `README.fa.md`

- Version → `2.8.0`; badges → `release-v2.8.0`; both README intros gained the churn clause
  (Farsi written natively, Persian digits ۲٫۸٫۰).
- TECHNICAL: the `fake-mode: sum` bullet now documents the 2.7.1 damage bug + the fix; new
  `fake-mode: seqsum` bullet; new `pool-rotate` flag-table row; `fake-mode` row mentions seqsum;
  new 2.8.0 release-history entry (with the explicit "if you run fake-mode: sum on 2.7.x, update
  the client" callout).

### Modified — `RESEARCH.md`

- §2 item 1 marked **Implemented in 2.8.0** (time axis; byte axis reserved in the API).
- §2 item 3 marked with the seqsum addition + the checksum-damage fix post-mortem.
- §3 carries the correction: marker IP-fragmentation is NOT free under frag-dropping rules (#640)
  — gate behind a path probe, default off (NOT implemented this round; see "Not done" below).

## Verification (this Windows box)

- `go build ./...` ✅ · `go vet ./...` ✅ · `GOOS=linux go build ./...` ✅
- `go test -count=1 ./cmd/...` — 29 pass ✅
- Target suite (`TestDesync|TestFake|TestValidateDesync|TestTCPChecksum|TestRollRotate|TestRotateDue`)
  — **40 consecutive full iterations pass** ✅ (this is the run that caught the sum bug: before the
  fix, `TestDesyncSumModeFiresOnData`/`TestDesyncSeqSumSendsBoth` failed ~50 % of runs)
- Full `wat/` suite: not run to completion (same load-flakiness caveat as every round; nothing in
  2.8.0 touches session/cc/ICMP hot paths — churn lives in the pool health check, and the only
  desync change is the marker builder).
- Raw-socket half (real marker transmission, real rotate recycling) still needs a Linux +
  CAP_NET_RAW box — unchanged caveat, now with TWO features awaiting field validation.

## Not done / next steps for another agent

1. **Field-validate 2.8.0 on a real Iran path** (the standing queue item): `pool-rotate: 30m` on a
   long session, `fake-mode: seqsum` vs `sum` vs `seq`, watch `PoolRotates()` and the fake counters.
2. **Byte-axis churn**: `SetRotate`'s second argument and `rotBytes` are wired but the flag only
   exposes time. Add `-pool-rotate-bytes` (or extend the duration syntax) when a user asks.
3. **Filter telemetry + auto-mode** (RESEARCH-3 follow-up, specced in conversation): startup probe
   (SYN with listed/unlisted SNI, one seq marker, one sum marker, one fragmented hello) →
   `/stats` filter profile → auto-pick the fake mode. Supersedes manual mode selection.
4. **Marker IP-fragmentation**: only behind the frag-drop probe of item 3 (RESEARCH-3 §3
   correction) — never ship it as a free knob.
5. **ICMP ceiling governor** (RESEARCH-3 follow-up): ramp the ICMP rate until the reroute
   signature (RTT spike + loss, PathFeedback already sees both), binary-search down, cache per
   path. Turns the hardcoded 16 MB/s default into a learned per-path ceiling.
6. **ECH bootstrap ladder**: fetch the ECHConfigList THROUGH the icmp carrier when DoH is
   DNS-hijacked (10.10.34.34), then promote to wss+ECH.
7. **wattun-manager**: expose `pool-rotate` in the Iran wizard advanced block (one `read -e` ask +
   a config-key emit next to fake-sni; `bin_ver_ok 2.8.0` guard) and in Advanced settings; the
   refinement mission of AGENT-HANDOFF.md item 8 still stands on top of this.
8. Push `dev`, tag `v2.8.0` → release workflow; notes-file from the TECHNICAL 2.8.0 entry.
   Client-only update; server unchanged; no wire change; mixed versions fine.

---

# WatTunnel 2.8.1 - refinement round, step 1 + step 2 (branch `dev`)

Handoff for the next agent. `AGENT-HANDOFF.md` is the mission; this file is what actually landed.

## Step 1 - refinement of rounds 2.6.0-2.8.0 (commit `cc8cc3c`)

- `rotateDue` compared the byte budget against the DATAGRAM COUNT (~256x off at the 4096-byte pool MTU):
  now real bytes via `txSize`. New `rotatePick`: one recycle per tick, oldest-first, never drops the
  last usable connection.
- `Clone` dropped the dial hook (`carrier_tcp.go`): `n.hook.Store(c.hook.Load())` - every session
  beyond the first dialed bare, so `-fake-sni` only fired on session 1.
- Fake-SNI was dead on `tls`/`wss`/`h2`/`grpc`: `Wrap` unwraps the TLS/framing wrapper (`rawTCP`) instead
  of asserting a bare `*net.TCPConn`.
- `-pool-rotate-bytes` (`cmd/wattun/main.go`, `parseSize` suffixes, decimal units).
- `sumSeq` mirror base is per connection (two pool connections opening at once cross-set each other's).
- Tests in `wat/rotate_test.go`.

## Step 2 - `wattun-manager` resilient-UX redesign (this round)

One "resilience options" block instead of two scattered places, plus recallable profiles:

- Wizard (Iran, pool carrier, Linux): fake-sni name / mode (`seq|ttl|sum|seqsum`) / ttl, then
  `pool-rotate` and `pool-rotate-bytes`, all with `bin_ver_ok` guards. Profile pick happens first.
- Advanced settings: key `k` renamed "resilience" - the same five values, plus summary lines
  (`fake-sni`, `pool-rotate`, `pool-rotate-bytes`).
- `profile save|list|show|del|apply [NAME] [TUNNEL]`: writes `$CONF/profiles/NAME.env`
  (`FAKESNI/FAKEMODE/FAKETTL/POOLROT/POOLBYTES`, comments ignored on read, atomic `mv`), re-applies it
  to a tunnel and restarts it. Reaches users as `wattun profile ...` too: any non-flag first argument
  execs into the manager (`cmd/wattun/manager_unix.go`).
- Unattended: `--fake-mode seqsum`, `--pool-rotate`, `--pool-rotate-bytes`. **Latent bug fixed**: the
  `ni_parse` first case `--*)` swallowed `--fake-sni/--fake-mode/--fake-ttl`, so those flags always died
  with "Unknown option"; the value list now routes them into the value branch.
- Validators: `v_pool_rotate` (Go `time.ParseDuration` durations), `v_pool_bytes` (mirrors Go
  `parseSize`: case-insensitive, optional `B`, decimals), `v_fake_mode` (+`seqsum`).
- `MGR_VERSION=2026102001`.
- `test-manager.sh`: one runnable check (assert-based, no root/systemd/binary) for profiles, apply/clear,
  unattended flags and the validators. Run `bash test-manager.sh`.

**Guard style is HARD on purpose.** The config loader rejects unknown keys (`config.go:164`), so a
`pool-rotate:` line written for a 2.7.x binary makes the tunnel REFUSE TO START. Config keys are flag
names (`flag.Lookup`), so `pool-rotate` / `pool-rotate-bytes` need no Go change.

Also fixed a test-only flake: `TestWriteLoopCountsBytes` kept the accepted conn in `_`, so the GC
finalizer closed it and the writer saw a dead connection under `-count>1`.

## Docs synced

- `wat/version.go` 2.8.1; release badges in both READMEs.
- `docs/TECHNICAL.md`: `pool-rotate-bytes` row, 2.8.1 release-history entry, `wattun profile ...` in the
  manager command block, advanced-settings bullet mentions resilience.
- `README.md` / `README.fa.md`: fake-SNI line now names `seqsum` and the byte budget, native Farsi.

## Verification (Windows box)

- `bash -n wattun-manager`, `bash -n install.sh`, `bash test-manager.sh` -> ALL OK, exit 0.
- `go build ./...`, `go vet ./...`, `GOOS=linux go vet ./wat/ ./cmd/wattun` -> clean.
- `go test ./cmd/wattun/` -> ok. `go test ./wat/ -run 'Rotate|Clone|WriteLoopCounts|SumSeq' -count=60` -> ok.
- NOT hardware-tested (needs Linux + CAP_NET_RAW/CAP_NET_ADMIN): real marker transmission, real churn
  recycling, and the wizard's unattended path end to end (needs a real token).

## Next (step 3, in priority order)

1. **Filter telemetry + auto-mode** - probe FIRST (SYN with listed/unlisted SNI, one seq marker, one
   sum marker) -> `/stats` filter profile -> auto-pick the fake mode. No marker IP-fragmentation before
   that probe exists (RESEARCH-3 §3 correction).
2. **ICMP ceiling governor** - ramp until the reroute signature (RTT spike + loss), binary-search down,
   cache per path. Replaces the hardcoded 16 MB/s default.
3. **ECH bootstrap ladder** - fetch the ECHConfigList through the icmp carrier when DoH is hijacked.
4. Byte-axis churn: done in 2.8.1 (`pool-rotate-bytes`) - field-validate next.
5. Push `dev`, tag `v2.8.1`, release notes from the TECHNICAL 2.8.1 entry.

---

# WatTunnel `dev` branch — next agent brief (2.8.0 → next)

You are continuing work on WatTunnel (`github.com/JohnWatsoon/WatTunnel`, branch `dev`, Go 1.26,
static linux/amd64+arm64). Read `CLAUDE.md` first, then `AGENTS.md`. One hard rule up front: every
commit, push, tag and release goes out under the owner's identity only
(`JohnWatsoon <133103370+JohnWatsoon@users.noreply.github.com>`); never add an AI name, trailer or
attribution line anywhere.

## Step 0 — read these files in order (they are the whole context)

1. `CLAUDE.md`, `AGENTS.md` — project rules (wire compatibility, docs sync, ICMP performance pins).
2. `CHANGES-SINCE-2.5.0.md` — every change since 2.5.0, why, and how it was decided (shortest, read first).
3. `RESEARCH.md` part 1 — design of the flow-marker feature (2.6.0).
4. `AGENT-HANDOFF.md` part 1 — 2.6.0 per-symbol map.
5. `AGENT-HANDOFF.md` part 2 — 2.7.0 + 2.7.1 per-symbol map; its "Not done" item 8 is the
   refinement mission, only partly closed by 2.8.1 step 1.
6. `RESEARCH.md` part 2 — method research behind 2.7.0/2.7.1 (decision table, verdicts).
7. `RESEARCH.md` part 3 — field status after the 2026 filter upgrades and what was implemented in
   2.8.0.
8. `AGENT-HANDOFF.md` parts 3-5 — 2.8.0 and 2.8.1 per-symbol maps, the "Not done" queue and the
   environment notes.
9. `docs/TECHNICAL.md` — every flag/config key/troubleshooting entry (the flag table and the
   Fake-SNI chapter covers 2.6.0-2.8.1).

## Step 1 — fully refine everything added on this branch (the standing mission)

The branch carries four feature rounds on top of `main`'s `bf92665` baseline: 2.6.0 (flow marker),
2.7.0 (trigger fix, NAT-follow, auto-TTL, more carriers), 2.7.1 (`sum` mode, probe off-by-one fix,
manager support), 2.8.0 (`pool-rotate` churn, `seqsum` dual marker, checksum-damage fix). Go
through ALL of it end to end with fresh eyes:

- **Code**: `wat/desync.go`, `wat/desync_linux.go`, `wat/desync_other.go`, `wat/desync_test.go`,
  `wat/rotate_test.go`, the churn engine in `wat/carrier_tcp.go` (rotate fields/budget/health-check
  hook), and `cmd/wattun/main.go` (flag wiring). Look for anything the tests don't pin: wrap-around
  arithmetic, the interaction of churn with the slow-connection check and with bonding, error
  paths, the 2 s Wrap timeout story, counter overflow. The 2.8.0 checksum bug was found exactly
  this way (a test flaking ~50 %) — assume there is at least one more latent defect and hunt it.
- **Tests**: keep every pass at full determinism (2.8.0's target suite ran 40 consecutive
  iterations clean; hold that bar). Add what's missing (e.g. churn × keepSlow interaction, clone
  inheritance, `-pool-rotate` config parsing).
- **Consistency**: naming, comments and error strings across the four rounds were written in
  bursts — normalize them (the docs already use "flow marker"/"filter" wording; bring code comments
  in line, keeping flag names and identifiers verbatim).

## Step 2 — rethink how all of it is managed in `wattun-manager`

`wattun-manager` (bash UI) grew its fake-sni support organically (Iran wizard advanced block,
Advanced-settings `k` entry, `--fake-sni/--fake-mode/--fake-ttl` unattended flags; see the 2.7.1
section of handoff 2). Now that `pool-rotate` exists too, redesign the UX so it is one coherent
story instead of scattered asks:

- One "resilience options" block (wizard + Advanced settings + unattended flags in agreement):
  fake-sni name, mode (`seq|ttl|sum|seqsum`), ttl, and `pool-rotate`, with sensible grouped
  defaults and one-line explanations read from `docs/TECHNICAL.md`.
- Consider a named-profile idea: save/recall a working combination (`wattun-manager profile save
  NAME` writes a snippet the wizard can apply), so a user who found a working combination can
  re-apply it in seconds after a reinstall.
- Respect the existing manager conventions (MGR_VERSION unchanged, atomic `mv` on update, `page`
  for every screen, `/stats` as the only live state, `bin_ver_ok` guards for features newer than
  the installed binary). `bash -n wattun-manager` must pass.
- Keep 2.8.0's queue item in mind: expose `pool-rotate` with a `bin_ver_ok 2.8.0` guard.

## Step 3 — only after 1 and 2: pick up new work from the queue

In priority order (details and reasoning in `AGENT-HANDOFF.md` "Not done" and
`RESEARCH.md` §2):

1. Filter telemetry + auto-mode: a startup probe (SYN with listed/unlisted name, one seq marker,
   one sum marker, one fragmented hello) reporting a per-path profile to `/stats`, from which the
   client picks the marker mode itself. Do NOT implement marker IP-fragmentation unless this probe
   exists first — RESEARCH-3 §3 explains why (a fragmented hello can tag the flow on paths that
   drop fragments; default off, gated).
2. ICMP ceiling governor: learn the per-path rate ceiling from congestion feedback instead of the
   hardcoded default (ramp → signature → back off → cache with hysteresis). Must not touch the
   session/cc hot paths' pinned sim-test behavior.
3. ECH bootstrap ladder: fetch the ECH config through the icmp carrier when DNS-over-HTTPS is
   unavailable, then promote to the fast CDN path.
4. Byte-axis churn (`SetRotate`'s second argument is wired but unexposed) — small.

Whatever you pick: keep every project rule (old/new peers must interoperate — server unchanged and
no new frame types unless ignorable-by-old-peer; client-only where the docs say so; both READMEs in
content sync with native Farsi; benchmark numbers only from real measurements), keep the wording of
all docs and comments in the neutral engineering style already used on this branch, and finish with
`go build ./... && go vet ./...`, the cmd tests, the target suite at 40 clean iterations, and
`bash -n install.sh wattun-manager`. Commit under the owner identity only.

## Environment notes (this Windows box)

- Go needs workspace-local caches: set `GOCACHE=$PWD\.gocache`, `GOMODCACHE=$PWD\.gomodcache`,
  `GOPATH=$PWD\.gopath` before any go command (the shell runs at Low integrity).
- `git commit` from that shell fails on `.git/index.lock`; use one unconfined run for commits.
- Web search/fetch are unavailable in this environment; GitHub API via git's bundled curl with
  `--http1.1` works (`git -c http.sslBackend=openssl clone` also works).
- The full `wat/` suite times out on this box even on clean main (machine-load flakiness); run the
  targeted suites instead, and re-run the full suite on a quiet Linux box with `-timeout 600s`.
- The raw-socket halves (marker injection, real churn recycling) can only be field-validated on a
  Linux box with CAP_NET_RAW (+ CAP_NET_ADMIN for the ISN probe) — flag anything untested-on-
  hardware as such, as every handoff before you did.
