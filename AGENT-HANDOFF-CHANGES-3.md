# Agent handoff: what changed on branch `dev` (2.8.0)

Branch `dev` now carries 2.8.0 on top of 2.7.1 (`ce058b3` docs / `67b3842` research / `a9784c3`
wording pass). **Commit pending at the time of writing — this file is committed together with the
2.8.0 changes.** Server unchanged, wire unchanged, ICMP path untouched. Everything below is the
full per-symbol map, continuing the format of AGENT-HANDOFF-CHANGES-2.md (rounds 1–2). The
research that drove this round is RESEARCH-3.md; its §2 items 1 and 3 are now implemented.

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

### Modified — `RESEARCH-3.md`

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
   refinement mission of AGENT-HANDOFF-CHANGES-2.md item 8 still stands on top of this.
8. Push `dev`, tag `v2.8.0` → release workflow; notes-file from the TECHNICAL 2.8.0 entry.
   Client-only update; server unchanged; no wire change; mixed versions fine.
