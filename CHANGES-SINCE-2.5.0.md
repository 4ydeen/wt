# Every change since 2.5.0, mapped out

Scope: branch `dev`, `v2.5.0..HEAD` (2.5.1 → 2.8.2). For every release: what shipped, why it was
needed, how the decision was reached (including what was considered and rejected), what it costs,
and how it was verified. Deep per-symbol detail lives in `AGENT-HANDOFF.md`; the method research
behind the decisions lives in `RESEARCH.md`.

## Release map

| Version | Date | Scope | Wire format | Server needs update? |
|---|---|---|---|---|
| 2.5.1 | 2026-10-16 | cheaper stream buffers; speedtest cap | unchanged | optional (mixed versions fine) |
| 2.6.0 | 2026-10-19 | fake-SNI desync (`tcp`, `tls`) | unchanged | no |
| 2.7.0 | 2026-10-19 | marker actually fires; NAT follow; auto-TTL; `ws/wss/h2/grpc` | unchanged | no |
| 2.7.1 | 2026-10-19 | `fake-mode: sum`; ISN probe fix; manager support | unchanged | no |
| 2.8.0 | 2026-10-20 | `pool-rotate` churn; `fake-mode: seqsum`; checksum-damage fix | unchanged | no |
| 2.8.1 | 2026-10-20 | `pool-rotate-bytes`; fake-SNI on `tls/wss/h2`; `Clone` keeps the dial hook; manager resilience block + profiles; unattended-flag fix | unchanged | no |
| 2.8.2 (manager) | 2026-10-20 | resilience kit off the default wizard flow; type switches keep/strip it; profiles refuse off-Linux | unchanged | no |

Between the releases: a documentation restructure, a static release badge, the git-identity fix, a
neutral-wording pass, and the consolidation of the work logs into the three files you are reading.
All listed under their releases.

Every release above is **client-side only**: the Kharej server binary is functionally unchanged since
2.5.0, no wire format changed, and old server + new client (and the reverse) interoperate. That rule
shaped every decision below — it made each feature shippable without touching production servers.

## 2.5.0 — the baseline (context, not a change on this branch)

2.5.0 removed the tunnel's own speed cap (~50-60 MB/s on direct pool carriers). Three local fixes:
every acknowledgement used to walk every packet in flight (now each ack range is a binary search into
the sent list and the loss check stops at the first packet young enough); direct pools now send
16 KB datagrams by default (a quarter of the packets, seals and ack entries per byte; `mtu` still
overrides); reliable carriers acknowledge after 16 packets instead of 6 (the 2 ms bound unchanged).
Also in 2.5.0: WireGuard and other big UDP packets pass every carrier (split and rebuilt inside the
tunnel), traffic totals survive restarts, a Windows binary exists, and **m** on a tunnel's page
changes its connection type. Field: upload 49-55 → 149.7 MB/s on a production reverse tcp tunnel;
download stayed at 53 MB/s on the Iran end's single core — that is what 2.5.1 attacked.

## 2.5.1 — cheaper stream buffers (`58bd459`)

**What shipped.**

- `wat/stream.go`: a stream's received in-order bytes no longer sit in one self-growing slice. They
  now live in a queue of pooled 64 KB chunks: each byte is copied once in and once out, nothing
  grows, and a drained or idle stream holds no receive memory.
- The sender's buffer moves its live bytes to the front only when the acked front is at least half
  their size; otherwise the buffer grows, up to twice its cap.
- `cmd/wattun/speedtest.go`: `/speedtest` accepts `mb` up to 256 × `streams` (`34d461f`) — the
  server's 256 MB cap turned out to be per stream, so bigger runs were blocked by the flag, not the
  server; longer runs were needed to sample CPU in production.

**Why.** A CPU profile of the Iran end during a 16-stream download (2026-10-16) put about 25 % of
the tunnel's CPU into its receive buffers. The old design dropped the slice whenever the reader
caught up and re-grew it by doubling, moving unread bytes to the front at each end: the copies, the
zeroing of every new array and the GC behind them did most of that work. The sending end (Kharej)
had the mirror image: a buffer at its size cap moved all its unacked bytes for every write once the
front had freed a little (17 % of its CPU). Download was the one direction 2.5.0 had not improved,
and this profile said the money was in buffer management, not crypto or syscalls.

**How the decision was reached.** Copy that happens once per byte is acceptable; copies that
re-run as buffers grow and shift are not. A circular/ring buffer per stream was considered and
rejected: it would still copy on each read for the out-of-order path and needed a second
bookkeeping structure, while the chunk queue reuses the segment-queue shape the stream layer already
had. The 64 KB chunk size is a compromise — 60 datagrams' worth of payload per chunk keeps the queue
short, while staying too big to matter per allocation. The send-side "move only past half" threshold
is the same compromise: it removes the O(n) memmove per write but bounds the buffer at 2× cap so a
slow reader cannot grow memory without limit. Profile first, fix the top entry only, measure again.

**Cost / risk.** Both changes are local to each end and change nothing on the wire, so mixed
versions work and a rollback is a binary swap.

**Verification / field numbers.** Test tunnel (16 connections, BBR): download 57.5-70.9 →
64.8-116.0 MB/s across three 200 MB runs. Production reverse tcp tunnel, 2026-10-17: download 53 →
157 MB/s (200 MB) and 194.6 MB/s (~1.6 Gbit) on a 2 GB run; upload 149.7 → 276.1 MB/s; Iran RSS flat
at 149-161 MB (2.5.0: 77-197 MB). `go build` / `go vet` / `go test ./cmd/...` (29) and the stream
tests pass. Full story: `docs/TECHNICAL.md` § "Cheaper stream buffers (2.5.1)".

## 2.6.0 — fake-SNI desync (`bf92665`, 11 files, +695/−20)

**What shipped.** The `tcp` and `tls` client carriers gained `fake-sni: <name>`: on every pool
connection dial, the client injects exactly one raw extra packet that carries an extra TLS
ClientHello naming the allowlisted host — crafted so the DPI's reassembler reads it as the flow's
first flight, while the real server never accepts it. From then on the session's encrypted datagrams
ride a flow classified as TLS to an allowed site.

- `wat/desync.go` (portable): `FakeClientHello` (minimal RFC-conformant TLS 1.2 ClientHello,
  32 crypto/rand bytes, 2 ciphers, server_name + supported_groups + signature_algorithms),
  `DesyncConfig{SNI, Mode, TTL}`, `validateDesync`, `csum`/`tcpChecksum`/`htons` (moved here from
  `icmp_linux.go` so tests compile everywhere).
- `wat/desync_linux.go`: the AF_PACKET sniffer + injector state machine — outgoing SYN → ISN,
  inbound SYN-ACK → seq/ack, outgoing final ACK (`ack == synAckAck`) → `fire()`, which sends
  IPv4+TCP+hello with `seq = ISN+1−len(hello)` (below the stream start: the server counts it an old
  duplicate), PSH|ACK, window 0xffff, TTL 64. `Wrap` (the pool's dial hook) announces the 4-tuple and
  waits ≤ 2 s for the fire; on timeout the connection proceeds unclassified.
- `wat/desync_other.go`: non-Linux returns an error at startup (needs CAP_NET_RAW).
- `SetDialHook` on `TCPPoolClient` (`wat/carrier_tcp.go`): the injection seam into every pool dial,
  including lazy redials. No hook → dial path byte-identical.
- Flags `-fake-sni`, `-fake-mode seq|ttl`, `-fake-ttl`; config keys derive from them; wired into the
  `tcp` and `tls` client cases. Tests: 5 (`TestFakeClientHelloRealParser` feeds the hello to Go's own
  crypto/tls server and requires it to parse).

**Why.** The owner asked for availability under the January 2026 whitelisting regime (net4people
#626): the filter permit-lists flows by TLS ClientHello name. Reference project:
patterniha/SNI-Spoofing (wrong-seq extra ClientHello; the relay was modelled packet for packet),
with zapret and GoodbyeDPI for the broader variant catalogue (full method notes in `RESEARCH.md`).

**How the decision was reached.** Between the public property families — DPI dodges (fragmentation:
fails non-TLS carriers, and the `03 03`-version precedent in #626's record), domain fronting (not a
wire feature; the `sni` field already covers it), ECH (already shipped in 2.2.0), TLS-in-TLS padding
(rejected: cipher-sniffable compression ratio, too little entropy padding) — the fake-SNI marker was
the winner because it (a) matches a condition the filter demonstrably honors (the SNI permit list
itself), (b) is invisible to the server by construction (below-window seq ⇒ old duplicate, or
TTL-expiring midway), so no server/wire change, and (c) composes with existing camouflage (`sni` +
`fp: chrome` + `tls-frag` on the real hello). Rejected alternatives are recorded in `RESEARCH.md`
with reasons.

**Cost / risk.** Client-only; Linux + CAP_NET_RAW (like the `icmp` carrier, so no new deployment
constraint). Known failure modes documented up front: a NAT that rewrites sequence numbers
inconsistently defeats seq mode; TTL mode needs a hop-count estimate; `h2c` accepts the flag but
gains nothing. Field risk from #626: the same method lived ~4 days in January in some networks before
NAT normalization — that risk is why the mode is a flag, not a default.

**Verification.** Linux build + vet on the Windows box; 29 cmd tests + 5 desync tests pass; full
`wat/` suite on clean main also times out on this box (known load flakiness, not this round);
`bash -n install.sh wattun-manager` clean. The raw-socket half is untestable on Windows (needs
Linux + CAP_NET_RAW) — flagged in the handoff.

## 2.7.0 — the marker actually fires (`d355a05`, 13 files, +1490/−209)

**What shipped.** A full re-audit of 2.6.0 while re-deriving the mechanics from zapret's
zero-stage/second-stage split found the trigger bug: 2.6.0's sniffer only tracked handshakes for
4-tuples already announced by `Wrap`, but `Wrap` runs *after* `dial()` returns — the kernel's SYN,
and usually the SYN-ACK and final ACK, are already on the wire before any announcement, so the
state machine's first two transitions never matched and every connection silently degraded to the
2-second unclassified fallback. The marker had never actually fired on a normal dial. Fixes and
hardening:

- Portable tracker (`wat/desync.go`, testable on every OS; the Linux file only sniffs/injects):
  - *early path*: probe the stream start off the socket with `TCP_REPAIR`/`TCP_REPAIR_QUEUE`/
    `TCP_QUEUE_SEQ` (the only kernel interface exposing a socket's sequence numbers; CAP_NET_ADMIN),
    announce `(isn, known=true)`; fire on the handshake's final ACK **or** the first data segment,
    whichever comes first.
  - *late path*: probe unavailable → fire anchored to the first outbound **data** segment only,
    never bare ACKs (bare-ACK anchoring would mis-place the marker).
- **NAT-sequence follow**: the SYN-ACK's ack cross-check rewrites `synSeq = ack−1`, so a uniformly
  rewriting NAT keeps the marker below where the stream starts *as the server sees it* — the exact
  failure that killed seq mode in some ASNs in January.
- **Auto-TTL**: `fake-ttl: 0` (now the default) learns the peer's inbound TTL from any SYN-ACK and
  sends the marker one hop short of the server — no traceroute needed.
- **Carrier scope**: also wired into the `wss`, `h2`, `grpc` client cases (the dial hook is shared
  pool machinery; `h2c` rides along but is pointless on cleartext). 16 tests.

**Why.** The feature's value was zero until it fired. This round was triggered by the research pass
(`RESEARCH.md` §1.1) re-deriving the trigger from the reference projects. Everything else built
this round (NAT follow, auto-TTL, more carriers) removes the field failure modes that made the
method fragile in January.

**How the decision was reached.** The kernel does not expose a socket's ISN (`tcp_info` has no such
field — checked against `x/sys/unix.TCPInfo`), so either read the wire (fragile: NAT/order) or probe
the socket (needs CAP_NET_ADMIN, which ICMP-carrier deployments already have). Both, in preference
order, with graceful fallback — never fail startup over the probe. Re-segmentation of the *real*
ClientHello (zapret multisplit/multidisorder) was considered for the same round and deliberately
deferred: it needs the TLS stack's first write intercepted and segmentation taken over with an
NFQUEUE data path — an architecture change with no established field regime where it beats the
marker. Verdict recorded as LATER with reasons (`RESEARCH.md` §1.2).

**Cost / risk.** Client-only, server unchanged, no wire change. 2.6.0 and 2.7.0 interoperate in
both directions (old server + new client and vice versa work — the marker is a side-channel packet
the server never sees).

**Verification.** 16 desync tests pass on Windows (this is why the tracker was made portable — the
state machine is unit-tested without hardware). `GOOS=linux` build clean; cmd tests 29 pass. Raw
halves still hardware-flagged.

## 2.7.1 — sum mode + probe off-by-one (`27ccdf3`, 11 files, +301/−30)

**What shipped.**

1. `fake-mode: sum` — the third variant, from GoodbyeDPI `--wrong-chksum` and zapret `FOOL_BADSUM`:
   the marker mirrors the first outbound data segment *in-window* (same seq, same ack, valid window)
   but with a damaged TCP checksum — the DPI parses before checksumming and sees the SNI; every
   server kernel drops it at checksum validation. Survives filters that check sequence numbers, where
   `seq`'s below-window marker reads as junk.
2. The probe off-by-one: `tcpStreamBase` returns SND.NXT (= ISN+1 right after the handshake), but
   `Wrap` announced it as the ISN — every early-path marker would have sat one sequence number too
   high, i.e. **in-window**, so the server would have accepted its bytes as real data (worst failure
   class). Fixed (`isn--` when known), pinned by `TestDesyncProbeIsnArithmetic`. Found by auditing
   the kernel's own accounting (`nf_conntrack_proto_tcp.c` window rules), not by a failing test —
   the tests pinned the wrong relation until this round.
3. `wattun-manager` fake-SNI support: Iran wizard advanced block with a hard `bin_ver_ok` gate,
   Advanced settings, `--fake-sni/--fake-mode/--fake-ttl` unattended flags, config keys emitted.
4. Domestic-relay recipe (RESEARCH §2.2's documentation promise) written into TECHNICAL.md as a
   no-code chain of two stock wattun instances. 19 tests now.

**Why.** Field context from the bbs records: some ASNs validate TCP state near the filtering hop, so
a below-window marker reads as junk there. Sum mode was chosen over adjusted-seq markers (zapret's
own docs: adjusted-seq markers are also ignored by some classifiers; adjusted-checksum markers fail
only behind checksum-validating NATs, and "ISPs usually pass" bad checksums).

**How the decision was reached.** Same rule as 2.6.0's design: prefer the mechanism that corrupts
nothing *by construction* on the server. Sum's correctness rests on checksum validation (guaranteed
by every conforming stack); seq's rests on below-window arithmetic surviving NAT rewrites (not
guaranteed). The off-by-one fix came from the same discipline: re-derive arithmetic from the
kernel's model; never trust the existing test's direction.

**Cost / risk.** Dies behind checksum-validating NATs (rare per field notes); needs a real data
segment to mirror, so it cannot fire on the final ACK alone; the mirror base would later need
per-connection isolation (fixed in 2.8.1 step 1).

**Verification.** `TestDesyncSumModeFiresOnData` + `TestDesyncSumModeLate` pin seq/ack/checksum
damage; `TestDesyncProbeIsnArithmetic` pins the Wrap conversion. Docs: 2.7.1 release entry with the
user-facing explanations; manager flags/validators extended; `.gitignore` for the session's build
artifacts.

## 2.8.0 — connection churn, dual markers, checksum fix (`1001f04`, 11 files, +475/−34)

**What shipped.**

1. `pool-rotate: 30m` (client pools): each healthy pool connection is recycled after a jittered
   lifetime budget — ±40 % per connection, re-rolled on every recycle, floors 10 s/1 MB so a bad
   roll can never hot-loop the redialer. Churn runs through the pool's existing death path
   (`pc.fail()`), so in-flight data is drained/dropped and the session resends; the slot redials
   immediately. Answers the field's strongest behavioral tell (#649: "a TLS flow held open for hours
   moving tens of GB is anomalous regardless of a perfect handshake") and the #628
   throughput→probe→block pattern. Code: `rollRotate`, `rotateDue`, `SetRotate`, `poolRotates` in
   `wat/carrier_tcp.go`.
2. `fake-mode: seqsum` (experimental): BOTH markers per connection ~1 ms apart — the below-window
   seq fake first, then the in-window bad-checksum mirror. A filter must discard both correctly to
   miss the SNI: window-junk dropping alone does not stop the sum marker; checksum dropping alone
   does not stop the seq marker (the GoodbyeDPI wrong-seq + wrong-chksum double-fake pattern).
3. **The checksum-damage fix (safety-critical).** 2.7.1's damage formula `(checksum ^ 1) - 1` is an
   identity for every *even* checksum: with bit 0 zero, `^1` sets it and `-1` clears it again — the
   checksum shipped unchanged, fully VALID. About half of all sum-mode markers carried a valid
   checksum and the server would have accepted their payload as real stream data — flow corruption,
   the exact failure the damage was meant to make impossible. Fixed to `checksum - 1` with a wrap
   guard (`- 2` when `-1` lands on `0xffff`, the valid fold of a correct packet), plus a doc comment
   carrying the post-mortem so the identity shape is never reintroduced. **If you run
   `fake-mode: sum` on 2.7.x, update the client.**
4. Tests: `rotate_test.go` (jitter bounds, due-semantics); desync tests up to 21 (seqsum sends both
   markers with the right seq/ack/checksum properties on early and late paths).

**Why.** RESEARCH.md part 3's field audit concluded the countermove is behavioral, not packet-shaped:
lifetime × volume classification. Churn is the best speed-per-effort item (zero wire change; the
redial happens at a chosen moment). The sum bug was found by running the target suite 40
consecutive full iterations — a one-shot pass hides a 50 % coin-flip bug; the iteration caught
`TestDesyncSumModeFiresOnData` failing ~half the runs, which led straight to the even-checksum
identity.

**How the decision was reached.** Churn was adopted from Hedioum (#649) but made per-connection and
jittered rather than uniform: a fixed reconnect period would itself be a fingerprint. tx accounting
rides the existing datagram counter (lock-free, near-uniform size). Byte-axis churn was reserved in
the API (`SetRotate(d, bytes)`) but not exposed — shipped in 2.8.1 once the byte accounting bug was
fixed. Fragmenting markers and re-segmenting real hellos were rejected again: the upgraded DPI
reassembles fragments (#640), so a fragmented marker can tag the very flow it was meant to save —
gated behind a path probe in the research, never shipped as a free knob.

**Cost / risk.** Client-only, server unchanged, no wire change. Churn cost ≈ 0; the seqsum pair adds
~2 packets per connection lifetime.

**Verification.** `GOOS=linux` build; target suite **40 consecutive full iterations** pass; cmd tests
29 pass. Full `wat/` suite still not run to completion on this box (standing load caveat; nothing in
2.8.0 touches session/cc/ICMP hot paths).

## 2.8.1 — step 1: refinement pass; step 2: manager redesign (`cc8cc3c`, `7378fde`)

**Step 1 — refinement of 2.6.0-2.8.0 (`cc8cc3c`, 5 files, +134/−28).** Bugs found by re-reading the
new code paths against their own invariants:

- **`rotateDue` counted datagrams, not bytes** (`carrier_tcp.go`): the byte budget was compared
  against the DATAGRAM COUNT (~256× off at the 4096-byte pool MTU) — a `pool-rotate-bytes: 4G`
  budget would have recycled after ~16M datagrams instead of 4G bytes. Now real bytes via the
  `txSize` accounting the pool already keeps. New `rotatePick`: one recycle per health-check tick,
  oldest-first, and never the last usable connection — churn must not take a pool of 1 to zero.
- **`Clone` dropped the dial hook** (`carrier_tcp.go`): `n.hook.Store(c.hook.Load())` was missing, so
  every session beyond the first (`-sessions > 1`) dialed bare and `-fake-sni` fired only on
  session 1 — silent partial coverage, the nastiest kind: it works in a 1-session test and
  silently degrades in production.
- **Fake-SNI was dead on `tls`/`wss`/`h2`/`grpc`**: `Wrap` asserted a bare `*net.TCPConn`, but on
  those carriers the pool wraps the connection in the TLS/framing layer before the hook sees it.
  `Wrap` now unwraps to the raw TCP conn (`rawTCP`).
- **`pool-rotate-bytes` flag** (`cmd/wattun/main.go`): `parseSize` suffixes, decimal units; combined
  with `pool-rotate`, whichever budget hits first recycles.
- **Per-connection `sumSeq`** (`desync.go`/`desync_linux.go`): two pool connections opening at once
  could cross-set each other's sum-mode mirror base; the base is now owned by the connection record,
  not the tracker.
- Test flake fixed: a rotate test held the accepted conn in `_`; the GC finalizer closed it mid-read
  under `-count>1`.

**Step 2 — manager resilience redesign (`7378fde`, 8 files, +376/−41).**

- One "resilience" block instead of two scattered places: Iran wizard (fake-sni name / mode
  `seq|ttl|sum|seqsum` / ttl, then `pool-rotate` and `pool-rotate-bytes`) and Advanced settings
  (`k` renamed "resilience", summary lines added). All `bin_ver_ok` guards are hard because the
  config loader rejects unknown keys (`config.go:164`) — writing a `pool-rotate:` line for a 2.7.x
  binary makes the tunnel *refuse to start*, so a soft guard would brick tunnels instead of failing
  politely. Config keys are flag names (`flag.Lookup`), so `pool-rotate`/`pool-rotate-bytes` needed
  no Go change — writing the key is the whole feature.
- `profile save|list|show|del|apply NAME [TUNNEL]`: the working fake/pool combination is saved to
  `$CONF/profiles/NAME.env` and re-applied after a reinstall or a tunnel type change (atomic writes,
  restart-on-apply). Reachable as `wattun profile ...` too — any non-flag first argument execs into
  the manager (`manager_unix.go`), so no new binary surface.
- **Latent unattended bug fixed**: `ni_parse`'s first case `--*)` swallowed
  `--fake-sni/--fake-mode/--fake-ttl`, so the 2.7.1 unattended fake flags always died with "Unknown
  option" — they had never worked. The value list now routes them into the value branch; also routed
  `--pool-rotate`, `--pool-rotate-bytes`; added `--fake-mode seqsum`.
- Validators mirror the Go parsers exactly: `v_pool_rotate` (durations), `v_pool_bytes`
  (case-insensitive suffixes, optional `B` — `500MB` was rejected before), `v_fake_mode` (+`seqsum`).
  Wizard default precedence fixed: unattended flag > loaded profile > empty (the profile-loaded fake
  mode was being reset to `seq`). `MGR_VERSION=2026102001`.
- `test-manager.sh`: one runnable assert-based check (no root/systemd/binary) for profiles,
  apply/clear, unattended flags and validators.

**Why.** Step 1 came from the "refine the existing rounds" mission: every new mechanism was written
against its own new tests, and a re-read of the *invariants* (bytes, not datagrams; the hook must
survive cloning; the hook must see the raw socket) found four silent-defect bugs — the worst kind,
because each looked correct in a one-session test. Step 2 came from the same mission's UX item: the
fake-SNI and churn knobs had grown into two scattered places in the manager, and the values that
matter most in the field (a working combination on a specific path) were the hardest to re-apply
after a reinstall.

**How the decision was reached.** Guard style was chosen hard on purpose, for the config-loader
reason above. Profile files were chosen over "remember the last used values" because a reinstall
wipes the config directory but a saved profile is explicit, named and reviewable (`profile show`
prints it). The profile format is a flat env file (KEY=VALUE, comments ignored on read) — the
simplest thing that survives shell quoting, and the manager can source it directly.

**Cost / risk.** Manager-only, no client/wire change. The `wattun profile` subcommand is additive;
existing manager flows are unchanged.

**Verification (Windows box).** `bash -n wattun-manager`, `bash -n install.sh`, `bash test-manager.sh`
→ ALL OK, exit 0. `go build ./...`, `go vet ./...`, `GOOS=linux go vet ./wat/ ./cmd/wattun` clean.
`go test ./cmd/wattun/` ok; `go test ./wat/ -run 'Rotate|Clone|WriteLoopCounts|SumSeq' -count=60` ok
(60 iterations — the flake fix proven, not assumed). NOT hardware-tested: real marker transmission,
real churn recycling, and the wizard's unattended path end to end (needs a live token).

## 2.8.2 — manager only: the resilience kit off the default flow (this round)

**What shipped.** The blackout/whitelisting survival kit (fake-SNI 2.6.0–2.8.0, pool-rotate
2.8.0–2.8.1) had grown into the plain-tunnel flow: the Iran wizard always walked every resilience
prompt, and Auto mode's type switches never cleaned the keys up. Manager-only fixes
(`MGR_VERSION=2026102002`):

- **Off the default flow**: the Iran wizard asks one explicit question ("Configure resilience
  options (fake-SNI, pool-rotate)? Only for censored routes; Enter = no"). Enter skips, with a
  pointer to tunnel page → o (advanced settings) → resilience for later; the success screen repeats
  that pointer when a tunnel was created without the kit. Unattended flags (`--fake-sni`,
  `--pool-rotate`, ...) and a saved profile still prefill the block and skip the ask — a preset IS
  the ask. Auto-token creations never offer the kit at all; auto type switches keep or strip the
  keys per the chosen variant.
- **Type switches keep or strip the kit** (`auto_apply`, the auto-test / change-type path): a
  working fake-SNI/pool-rotate combination survives switching to another single pool carrier in the
  normal direction — the only shape the desync layer attaches to (verified against
  `cmd/wattun/main.go:278/297/338`). Switching to `icmp`, `udp`, a bonded carrier or reverse deletes
  the keys instead of leaving them dead in the config (or silently re-arming them on a switch back):
  the Go config loader rejects those keys on carriers without the layer, so a stale `fake-sni:`
  line would keep the switched tunnel from starting.
- **Profiles are Linux-only**: `profile save` refuses off-Linux with the CAP_NET_RAW explanation
  (fake-SNI needs it, like the icmp carrier; a saved profile is meaningless where it cannot start).
- **Existing touchpoints unchanged**: the tunnel page's Advanced settings → resilience menu (and its
  `is_pool` gate, which correctly excludes bonded carriers) is untouched; `profile
  save|list|show|del|apply` and the unattended flags keep their 2.8.1 behavior. No Go change, no
  config-format or wire change.

**Why.** Owner direction: these transports exist strictly for blackout/whitelisting routes. A user
on a normal route must not meet them in the default flow, and must find them in one obvious place
when a censor escalates — one opt-in question plus a success-screen pointer is the smallest change
that does both without hiding the feature behind jargon.

**Cost / risk.** Manager-only. The wizard gains two branches; `test-manager.sh` stubs `uname` (its
sandbox must look like Linux for the profile tests) and now also asserts the off-Linux save gate.

**Verification (Windows box).** `bash -n wattun-manager`, `bash -n install.sh`, `bash -n
test-manager.sh` → 0 (Git Bash; WSL is not installed on this box). `bash test-manager.sh` → ALL OK,
exit 0, including the new off-Linux gate (rejected, nothing written). No Go changes this round.

## Docs and infra between the releases

- `d64f4d5`/`ed2c2cf`/`34d461f` — 2.5.1 docs and speedtest cap raising (**why**: `/speedtest`'s flag
  cap, not the server's 256 MB-per-stream cap, was limiting long CPU-sampling runs).
- `1febc67`/`6c0f081` — TCP field numbers into both READMEs; static shields.io release badge and
  windows in the platform badge (**why**: shields.io GitHub lookups fail under rate limits, and the
  dynamic badge rendered "unknown" on the filtered path where READMEs are read).
- `e6c11d2` — READMEs collapsed to a short front page (speed, comparisons, idle cost, setup); every
  detail moved to `docs/TECHNICAL.md`, which gained Release history and Resource usage. (**why:**
  keeping two full documents in two languages in sync was already failing; one short + one deep
  document keeps the sync surface small.)
- `8cc3ef0` — git identity set to the owner's noreply address (authorship rule).
- `a9784c3` — neutral wording pass over all branch docs (**why**: the research notes quoted field
  reports verbatim; the repo's purpose is published transport engineering, so wording was normalized
  without changing any technical claim).
- `67b3842` — the field-status research (now `RESEARCH.md` part 3).
- `a03ba93`/`ce058b3` — full-detail 2.7.0/2.7.1 handoffs; `40318f6` — NEXT-AGENT-PROMPT mission.
- `2026-10-20 consolidation` — this trio (`CHANGES-SINCE-2.5.0.md`, `AGENT-HANDOFF.md`,
  `RESEARCH.md`) replaces the per-round file pile so the next agent reads three documents, not eight.
  No technical fact was dropped in the merge; per-symbol detail stayed with the handoff, method
  verdicts with the research, round narratives here.

## Verification-status caveats (apply to all rounds)

- Everything code-side verifies on this Windows box: `go build`, `go vet` (host + `GOOS=linux`),
  cmd tests, desync/rotate/churn target suites (up to 60 consecutive iterations), `bash -n` on the
  shell scripts, and `test-manager.sh`.
- The full `wat/` suite repeatedly times out on this Windows box *including on clean main* — known
  load flakiness, suspected slow; it passes on prior rounds' quiet runs.
- **Hardware verification is outstanding for the whole fake-SNI + churn family**: real marker
  transmission through a filtering path, real churn recycling, TCP_REPAIR probing under real
  CAP_NET_ADMIN — all need a Linux host with CAP_NET_RAW (+ CAP_NET_ADMIN). Flagged in every handoff;
  nothing above is hardware-confirmed.
- Field validation queue (priority order): filter telemetry + auto-mode (probe FIRST — no marker
  IP-fragmentation before it per RESEARCH.md part 3 §3), ICMP ceiling governor, ECH bootstrap ladder,
  `pool-rotate-bytes` field validation. Details in `AGENT-HANDOFF.md` and `RESEARCH.md`.


## The consolidation (this round)

The work logs had accumulated as one file per round: `FAKE-SNI-DESIGN.md` (2.6.0 design),
`AGENT-HANDOFF-CHANGES.md` (2.6.0 map), `AGENT-HANDOFF-CHANGES-2.md` (2.7.0+2.7.1 map),
`RESEARCH-2.md` (permit-list/restricted-routing research), `RESEARCH-3.md` (post-upgrade field
status), `AGENT-HANDOFF-CHANGES-3.md` (2.8.0 map), `NEXT-AGENT-PROMPT.md` (next-agent brief),
`AGENT-HANDOFF-CHANGES-4.md` (2.8.1 map). Eight files, overlapping intros, cross-references chased
across files. They are now three:

- **`CHANGES-SINCE-2.5.0.md`** (this file) — every change since 2.5.0 with the reason and the
  thought process behind each; the release-by-release narrative.
- **`RESEARCH.md`** — all method research merged: the 2.6.0 flow-marker design (was
  FAKE-SNI-DESIGN.md), the permit-list/restricted-routing analysis and decision table (was
  RESEARCH-2.md), the post-upgrade field status and churn strategy (was RESEARCH-3.md).
- **`AGENT-HANDOFF.md`** — the per-round, per-symbol implementation maps (2.6.0 → 2.8.1) and the
  next-agent brief (queue, environment notes, verification status; was NEXT-AGENT-PROMPT.md).

The split is by *audience*, not by date: changes answer "what happened and why", research answers
"what does the network do and what options exist", handoff answers "where in the code is it and what
is left". User-facing docs are untouched by the consolidation — `README.md`, `README.fa.md`,
`docs/TECHNICAL.md` remain the manuals. `bench/results-2026-10-09-final.md` stays as-is (dated
measurement record). `CLAUDE.md` and `AGENTS.md` were not touched.

## Commit map (`git log v2.5.0..HEAD`)

| Commit | Release / kind | One line |
|---|---|---|
| `1febc67` | 2.5.0 docs | field numbers 2.4.17→2.5.0 in both READMEs + TECHNICAL.md |
| `6c0f081` | docs | static release badge (shields.io rate limits), Windows in platform badge |
| `58bd459` | 2.5.1 | cheaper receive/send buffers (download CPU on the Iran end) |
| `34d461f` | 2.5.1 | `/speedtest` mb up to 256 × streams; longer runs for CPU sampling |
| `d64f4d5` | 2.5.1 | docs, field numbers, release badge |
| `ed2c2cf` | 2.5.1 docs | production numbers: download 157-195 MB/s, upload 276 |
| `e6c11d2` | docs | short READMEs; details + release history + resource usage in TECHNICAL.md |
| `8cc3ef0` | meta | git identity = JohnWatsoon noreply address |
| `bf92665` | 2.6.0 | fake-SNI desync for the tcp and tls carriers |
| `d355a05` | 2.7.0 | fake-SNI hardened and fixed: the fake now actually fires |
| `a03ba93` | docs | full-detail 2.7.0 handoff (every symbol, trigger paths, tests, env notes) |
| `27ccdf3` | 2.7.1 | fake-mode sum, ISN probe fix, manager fake-sni support |
| `ce058b3` | docs | handoff covers 2.7.1 in full detail |
| `67b3842` | research | round 3: post-upgrade field status, whitelisted-service carriers, churn strategy |
| `a9784c3` | docs | neutral wording pass; handoff gains full-refine mission |
| `1001f04` | 2.8.0 | pool-rotate churn, fake-mode seqsum, fix the sum-marker checksum damage |
| `40318f6` | docs | next-agent brief (refine mission, manager UX redesign, queue, env notes) |
| `cc8cc3c` | 2.8.1 | byte-axis churn budget, fake-SNI on tls/wss/h2, clone inherits dial hook |
| `7378fde` | 2.8.1 | manager resilience block, profile save/apply, unattended fake/pool flags, docs sync |
| `a591706` | 2.8.2 (mgr) | resilience kit off the default wizard flow; switches keep/strip it; profiles Linux-only |
| `08f3641` | docs | consolidate the eight work logs into `RESEARCH.md`, `AGENT-HANDOFF.md`, this file |





