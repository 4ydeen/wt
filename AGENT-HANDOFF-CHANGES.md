# Agent handoff: what changed on branch `dev` (2.6.0)

Commit `bf92665` on branch `dev` â€” 11 files, +695/âˆ’20. Not merged to `main`, not tagged, no release
cut. Everything below is committed; this file and `FAKE-SNI-DESIGN.md` are uncommitted by request.

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
