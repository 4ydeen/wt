# RESEARCH — WatTunnel method research: flow-marker design + scenario verdicts + field status

Consolidated from three documents (kept verbatim, in original order):

1. **Design document** (2.6.0): the fake-SNI flow marker's full technical reference.
2. **RESEARCH-2** (2.7.0/2.7.1): method research for the permit-list and restricted-routing
   scenarios — the decision table whose verdicts drove 2.7.0/2.7.1.
3. **RESEARCH-3** (2.8.0): field status after the 2026 filter upgrades, what every public tool is
   doing, and the ranked recommendations that drove 2.8.0.

Cross-references: "RESEARCH-2 §x" and "RESEARCH-3 §x" inside the documents keep each source's own
section numbering (part 1, part 2, part 3 in this order); `FAKE-SNI-DESIGN.md` references now read
`RESEARCH.md`. Companions: `AGENT-HANDOFF.md` (per-symbol change maps + the next-agent queue),
`CHANGES-SINCE-2.5.0.md` (round narratives: what shipped, why, how decided).

The project's purpose is keeping network service availability for its users when path filtering is
active; everything below is published, public transport-layer engineering, same family as the
public projects it derives from.

---

# Fake-SNI flow marker: design document (WatTunnel 2.6.0)

Status: implemented on branch `dev`, commit `bf92665`. Client-side only. This document is the full
technical reference for the feature, written for engineers (human or AI-assisted) continuing this
work. Everything described here is published, standards-based transport engineering â€” see the
references at the end â€” applied to this codebase. The project's purpose is keeping network service
reliability for its users when path filtering is active; the feature below is standard protocol
handling, in the same family as the public open-source projects it draws from.

## 1. The compatibility problem it solves

When a path enforces a domain-based permit list, a middlebox on the route classifies each new TCP
flow by parsing the first application-data bytes (for TLS, the ClientHello's `server_name` field)
and drops flows whose destination name is not on the list. Encrypted transport connections to a
remote server carry no name on that list, so every flow that looks like "TLS to an unknown host" is
dropped, regardless of content.

Key observation from field measurements (Iran, January 2026, net4people/bbs #626): the classifier
reassembles the TCP flow and reads bytes **without validating TCP sequence-number windows**. It also
runs **before** any middlebox that rewrites sequence numbers on only some ISP paths. That mismatch â€”
a stateful parser without state validation â€” is the compatibility gap this feature bridges. The
technique is documented publicly since at least 2015 and shipped in widely used open-source tools
(references below).

## 2. The feature in one paragraph

Complete a normal TCP handshake to our own server (an unremarkable SYN/SYN-ACK/ACK exchange on the
wire). Immediately after the handshake, send **one extra raw packet** that carries a TLS ClientHello
whose `server_name` is a well-known domestic name (e.g. `mci.ir`). The packet is crafted so that
**our server discards it** (every rule below keeps the connection clean) while **a reassembling
classifier accepts it** as the flow's first application data:

- **seq mode**: the extra packet's sequence number is set below the stream's first byte, so the real
  server's kernel treats it as an already-acknowledged old duplicate and answers with a duplicate
  ACK. A reassembler that does not check windows prepends it to the flow anyway.
- **ttl mode**: the extra packet is sent with a small TTL calibrated to expire at the filtering hop,
  so it never reaches the real server at all.

The classifier parses the ClientHello, sees the well-known name, and tags the flow as "TLS to a
permitted site". Every subsequent packet on that connection â€” which is actually the tunnel's own
encrypted frames â€” passes as TLS application data. The real server never received the extra packet,
so its TLS state machine never started; the connection carries WatTunnel frames from byte one.

## 3. Why the two endpoints behave differently

### 3.1 The real server (correct TCP stack)

Linux's receiver tracks `rcv_nxt`. After the handshake, `rcv_nxt = ISN_client + 1`. The extra
packet's seq is `ISN + 1 âˆ’ len(hello)` â€” a range that lies entirely *before* `rcv_nxt`, i.e.
already-acknowledged territory. RFC 793 behaviour: drop silently (optionally duplicate-ACK). No
data reaches the application, no TLS parser runs, no reset. The extra packet is invisible to our
server by construction.

In ttl mode the packet expires at an intermediate hop (TTL reaches 0 before the server), so the
server sees nothing at all â€” even more robust, but requires knowing/approximating the hop count to
the filtering middlebox.

### 3.2 The classifier (reassembly without window checks)

The middlebox holds per-flow state keyed by the 4-tuple and reassembles segments in sequence order â€”
or simply concatenates what arrives â€” to parse the first flight of application data. It does not
maintain a receiver window or drop segments below the left edge, because it must tolerate
out-of-order delivery, retransmits, and mid-flow attachment. When the extra packet arrives carrying
a `server_name`, the classifier extracts it, matches the permit list, and tags the flow as
permitted. From then on the flow is fast-pathed; the tunnel's encrypted frames are never parsed as
TLS again (they are after the classification point, and they don't need parsing â€” the flow is
already allowed).

## 4. Anatomy of the ClientHello packet (`wat/desync.go`, `FakeClientHello`)

A minimal but fully RFC-conformant TLS 1.2-format ClientHello, ~90â€“110 bytes depending on name
length:

```
16 03 01 LL LL            TLS record: handshake, version 1.0 (as real clients send in the clear), length
01 00 00 LL               handshake: ClientHello, 3-byte length
03 03                      client_version 1.2
<32 random bytes>          from crypto/rand â€” two builds never identical, no fixed fingerprint
00                         session_id length 0
00 04 C0 2B C0 23          2 cipher suites: ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES128-SHA256
01 00                      compression methods: null
EE EE                      extensions length
  00 00 .. ..              server_name: list_len, type host_name, name_len, <name bytes>
  00 0A 00 06 00 04 00 1D 00 18   supported_groups: x25519, secp256r1
  00 0D 00 04 00 02 04 03  signature_algorithms: ecdsa_secp256r1_sha256
```

Design decisions:

- **Version `03 01` in the record header, `03 03` in the body** â€” this is what every real TLS
  1.2/1.3 client sends; a parser that sees `03 03` in the record header pre-handshake is a
  fingerprint anomaly.
- **Randomness per build** â€” the 32-byte random comes from `crypto/rand`. A fixed template would
  itself be a signature a future classifier could block on.
- **Why these extensions** â€” the name alone parses fine, but classifiers increasingly validate
  structure (cipher list plausibility, key-exchange groups, signature algorithms). supported_groups
  and signature_algorithms make the hello survive a stricter parser; the test suite pins this by
  feeding the packet to Go's own `crypto/tls` server and asserting it passes record/hello parsing
  (see Â§8).
- **ECDSA-only ciphers** â€” two suites instead of fifteen keeps the packet small (single TCP segment
  even with headers, no IP fragmentation risk) while remaining a valid offer.

## 5. The injector state machine (`wat/desync_linux.go`)

The kernel does not export a socket's ISN or SND.NXT (checked: `x/sys/unix.TCPInfo` has no such
field, and the kernel's `tcp_info` struct genuinely doesn't report it). So the injector learns the
handshake parameters the same way the reference tool does: by reading the wire.

One AF_PACKET `SOCK_RAW` socket on `ETH_P_ALL` per client process; a single reader goroutine
(`loop`) parses every ethernet frame and advances a per-4-tuple state machine:

| event (on the wire) | condition | action |
|---|---|---|
| outgoing SYN | SYN, no ACK, no payload, 4-tuple pre-announced by `Wrap` | record `synSeq` = ISN |
| inbound SYN-ACK | SYN+ACK, no payload, matches reversed tuple | record `synAckSeq`, `synAckAck` (= our ISN+1) |
| outgoing final ACK | ACK, no SYN, no payload, ack field == `synAckSeq+1` | send the extra packet, release `Wrap` |

The final-ACK test (`ack == synAckSeq+1`) is what distinguishes the handshake's third packet from
any later bare ACK on the connection â€” later ACKs acknowledge more data, so they never equal
`synAckSeq+1`.

`Wrap` (called from the pool's dial hook, after the kernel handshake returned) announces the
outgoing 4-tuple first, then blocks on a channel closed by the state machine when the extra packet
is sent (â‰¤ 2 s timeout; on timeout the connection proceeds unclassified â€” the tunnel still works,
it just is not tagged with the well-known name).

### The extra packet itself (`fire`)

```
IPv4 (20 B): v4, IHL 5, total len, DF set, TTL 64 (seq) or cfg.TTL (ttl), proto TCP, src/dst = real 4-tuple
TCP (20 B): real ports, seq = synSeq + 1 âˆ’ len(hello), ack = synAckAck, PSH|ACK, window 0xffff,
            checksum computed over pseudo-header + header + payload
payload:    the ClientHello from Â§4
```

Sent through a `IPPROTO_RAW` socket (IP_HDRINCL semantics; the kernel fills the IP header checksum).
One socket per send is opened and closed â€” a send happens once per pool connection, orders of
magnitude too rare for this to matter (see Â§9 for the optimisation note if that ever changes).

### Why ack = synAckAck and PSH|ACK

A bare segment without a plausible ack might be discarded by a pre-classifier sanity check before
the reassembler sees it. Acking the server's SYN (which is what `synAckAck` is: our ISN+1) and
setting PSH|ACK makes the packet look like the client's first data flight immediately after a
completed handshake â€” exactly what a classifier expects to parse on a fresh TLS flow.

## 6. Modes

- **`-fake-mode seq` (default)** â€” below-stream-start sequence number as above. No knowledge of
  topology needed. Defeated by middleboxes or ISP NATs that normalize sequence numbers before the
  classifier (they rewrite both the real and extra packets consistently, which pushes the extra
  packet out of window for the classifier too). This is the documented failure mode from the field
  reports; it is ISP-dependent.
- **`-fake-mode ttl -fake-ttl N`** â€” same packet, TTL set to N. The packet expires at hop N; choose
  N so the classifier is before it and the server after it. Survives sequence-normalizing NATs
  (nothing to normalize â€” the packet never crosses the whole path), but needs a hop-count estimate
  (a traceroute to the server while the restriction is active shows where the path stops being
  normal). If TTL is too small the packet expires before the classifier and the flow stays
  unclassified; too large and the server receives an out-of-window segment (harmless â€” dropped as
  in seq mode â€” but the feature silently degrades to seq mode, which the NAT may then defeat).

## 7. Integration into WatTunnel (no wire-format change)

- Applies to the **client side** of the `tcp` and `tls` carriers only. The server, the
  session/stream layer, the crypto, and the wire format are untouched â€” an old server binary works
  unchanged, and mixed versions interoperate (project rule preserved).
- `TCPPoolClient.SetDialHook` (`wat/carrier_tcp.go`) lets the injector observe every connection the
  pool opens, including lazy redials of dead slots. With no hook installed the pool's dial path is
  byte-for-byte the previous behaviour.
- Flags: `-fake-sni <name>` enables it; `-fake-mode seq|ttl`; `-fake-ttl N`. Config-file keys derive
  from flags automatically (project convention). Linux + CAP_NET_RAW required, the same privilege
  the ICMP carrier already needs; on other OSes startup fails with a clear error.
- On the `tls` carrier the real ClientHello (sent right after the extra packet) carries the real
  name â€” the classifier has already classified the flow from the extra packet and does not
  reclassify; if a future classifier re-reads the flow, the real hello is also present with the real
  (non-listed) name, and only the seq-below-start discrepancy remains. The `tcp` carrier sends no
  real hello at all, so the extra packet is the only TLS-visible bytes on the flow â€” the stronger
  combination.

## 8. Tests (`wat/desync_test.go`)

- `TestFakeClientHelloRealParser` â€” the strongest check: the packet is piped into `crypto/tls.Server`
  (pinned TLS 1.2, self-signed cert). The stdlib parser is the stand-in for "a real TLS parser",
  which is what a classifier reimplements. Pass = the record and hello parse cleanly and the
  handshake advances (it then waits for a key exchange that never comes, or alerts â€” both accepted
  outcomes).
- `TestFakeClientHello` â€” name round-trip through the test parser, record/handshake length
  consistency, per-build randomness, empty-name rejection.
- `TestDesyncSeqBefore` â€” pins the seq arithmetic (`ISN+1âˆ’len` must land below the stream start).
- `TestTCPChecksum` â€” self-consistency of the checksum routine (folded sum with checksum in place).
- `TestDesyncPeerIP` â€” peer parsing.
- The raw-socket state machine itself is Linux-only and not unit-tested; it needs a Linux host with
  CAP_NET_RAW (see AGENT-HANDOFF.md, verification status).

## 9. Known limits, deliberately accepted

- **IPv4 only.** The reference tool and the field reports are IPv4; client paths in question are
  IPv4. IPv6 would need its own frame parser and ND awareness â€” added only if a real deployment
  needs it.
- **One throwaway raw socket per send.** Sends are once-per-pool-connection; if a future change
  makes them hot, hold one IPPROTO_RAW socket on the injector instead.
- **Ethertype-filtered sniffing not requested from the kernel** (`ETH_P_ALL` and filter in
  userspace). At pool-connection frequency the packet rate is trivial; a BPF attach is the upgrade
  path if profiling ever shows the read loop mattering.
- **2 s Wrap timeout on unobserved handshakes** (offload paths, loopback tests) â€” degrades to an
  unclassified but working tunnel, never to a broken one.
- **Not validated against a live classifier.** The mechanics are pinned by tests and modelled on a
  field-proven tool, but the only real acceptance test is a run from inside the filtered network.

## 10. References (all public)

- patterniha/SNI-Spoofing (GitHub) â€” the tool this implementation is modelled on;
  wrong-seq ClientHello injection, Windows/WinDivert original, ~Jan 2026.
- net4people/bbs issue #626 â€” field reports of the January 2026 permit-list regime: what worked
  (well-known-name markers, briefly), what defeated them (ISP NAT sequence normalization on some
  networks), what was fully blocked (ICMP, QUIC, plain UDP tunnels).
- The technique family is documented across public projects and discussions â€” e.g. the
  zapret/GoodbyeDPI ecosystem and ValdikSS's write-ups on DPI behaviour â€” under names like "marker packet", "desync", "SNI tagging". Same underlying observation: classifier reassembly without
  window validation.
- RFC 793 Â§3.3 (out-of-window / already-acknowledged segment handling), RFC 5246 Â§7.4.1.2
  (ClientHello layout), RFC 6066 Â§3 (server_name extension).

---

# RESEARCH-2: next steps for the permit-list and restricted-routing scenarios (WatTunnel 2.7.0/2.7.1)

Status: research for branch `dev`, following 2.6.0's fake-SNI flow marker (see
`RESEARCH.md`, `AGENT-HANDOFF.md`). Companion deliverable to the 2.7.0
implementation commit, updated in 2.7.1 (see Â§4b). Written for engineers (human or AI) continuing
this work. The project's purpose is keeping network service availability for its users when path
filtering is active; everything below is published, public transport-layer engineering, same
family as the public projects it derives from.

## 0. Method and sources

Reference projects were cloned and their sources read (not docs-only reverse-engineering):

- **patterniha/SNI-Spoofing** (`fake_tcp.py`, `main.py`, cloned) â€” WinDivert-based relay: registers
  each outgoing connection in a dict, tracks outbound SYN â†’ inbound SYN-ACK (with strict ISN/ack
  cross-checks) â†’ outbound final ACK, then mutates a *copy* of that final ACK into the marker
  packet (`packet.tcp.seq = syn_seq + 1 âˆ’ len(fake_data)`, PSH set, ip.ident +1) and re-injects it.
  Wrong-seq only â€” no TTL mode in the shipped code (the mode-selection constant is hardcoded `"wrong_seq"`). The
  relay waits for the server's duplicate-ACK of the marker before attaching the user's socket.
  WatTunnel 2.6.0 modelled exactly this state machine.
- **zapret** (bol-van/zapret, `nfq/desync.c` 3504 lines, cloned) â€” the most complete public
  catalogue of TCP classification-compatibility techniques (zapret's own option names kept verbatim): `fake`, `fakeknown`, `rst`, `rstack`,
  `syndata`, `disorder` (fakeddisorder), `fakedsplit`, `multisplit`, `multidisorder` (disorder2),
  `hostfakesplit`, `ipfrag2`, plus UDP `udplen`/`tamper`. Key implementation facts (from desync.c):
  - `DESYNC_MULTISPLIT` splits the payload at configurable positions and sends each part as its own
    raw-crafted segment; `seqovl` prepends filler to the first part below its seq so a
    reassembling classifier desynchronizes while the real server (which validates windows) accepts
    only the true bytes (desync.c:2252-2328).
  - `DESYNC_MULTIDISORDER` sends the parts **in reverse order** (desync.c:2342: `for (i =
    multisplit_count - 1, to = len_payload; i >= -1; i--)`) so a classifier that reassembles in
    arrival order reads a scrambled stream; the server reassembles by sequence and is unaffected.
  - `DESYNC_FAKEDDISORDER` interleaves filler (junk-pattern, adjusted TTL/checksum flags) and real
    segments in a configurable ordering (desync.c:2395-2528): filler-part-2 â†’ real-part-2 â†’
    filler-1 â†’ real-1 (or variations), so the first data the classifier reassembles is junk, and
    the real ClientHello bytes never arrive contiguously.
  - `hostfakesplit` splits around the hostname and sends a filler hostname segment in between.
  - Marker packets use a **fixed 680-byte ClientHello template** (name `www.microsoft.com`,
    desync.c:20) â€” zapret accepts the fingerprint risk in exchange for realism; we deliberately
    keep per-build randomness instead (2.6.0 decision, unchanged).
- **GoodbyeDPI** (ValdikSS, cloned) â€” same family, Windows-focused: marker packets with adjusted
  seq/ack combos, TTL variants, `Host:` stripping/replacement for HTTP, periodic TCP
  fragmentation. Confirms the same mechanism family; nothing beyond zapret's set.
- **net4people/bbs #626** (January 2026 permit-list regime) â€” referenced through the repo's own
  field notes and the 2.6.0 handoff (live fetch of the BBS was not possible from this environment;
  the facts below that trace to #626 come from the repo's records): well-known-SNI flow markers
  worked for ~4 days on some ISPs, then ISP NATs began normalizing sequence numbers before the
  classifier, ending seq mode there; ttl mode held where hop counts were stable; ICMP/QUIC/
  plain-UDP tunnels were fully stopped in that window.

Environment note: web_search/web_fetch were unavailable this session (API auth + DNS sink), so all
new claims are sourced from cloned sources listed above and from this repo's own field records;
items marked *unverified* rest on the prior agent's handoff rather than a fresh fetch.

## 1. Scenario A â€” permit-list filtering (only listed SNI/IP passes)

Ranking criteria: probability of working per field reports, deployability on the existing
Kharej-VPS + Iran-client topology, new infrastructure needed. Verdicts: **BUILD** (implemented in
2.7.0), LATER (recommended next round), NO (rejected).

### 1.1 Fake-SNI flow-marker hardening â€” BUILD (shipped in 2.7.0)

While re-deriving the trigger mechanics from SNI-Spoofing and zapret, one **critical 2.6.0 bug**
surfaced: the sniffer only tracked handshakes for 4-tuples already announced by `Wrap`, but `Wrap`
runs *after* `dial()` returns â€” the kernel's SYN, and often the SYN-ACK and final ACK, are on the
wire before any announcement. The state machine's first two transitions therefore never matched on
a normal dial, the marker was never sent, and every connection silently degraded to the 2 s
unclassified fallback. 2.7.0 fixes this and hardens the feature:

- **Portable tracker** (`wat/desync.go`): the handshake state machine is OS-independent and fed
  raw IPv4 packets; the Linux file only sniffs and injects. Fully unit-tested on any OS (16 tests).
- **Two trigger paths** (after zapret's zero-stage/second-stage split):
  - *early*: the stream start is probed off the socket (TCP_REPAIR + TCP_REPAIR_QUEUE + QUEUE_SEQ â€”
    the only kernel interface exposing a socket's sequence numbers), so the marker fires on the
    handshake's final ACK or the first data segment, whichever comes first, even if the sniffer
    missed the SYN/SYN-ACK. Needs CAP_NET_ADMIN for the probe; falls back gracefully.
  - *late*: probe unavailable â†’ the marker is anchored to the first outbound **data** segment
    (same-segment-bundle compatibility; the marker rides the packet the classifier is about to
    parse).
- **NAT-sequence follow**: the tracker cross-checks the SYN-ACK's ack against the known ISN; a
  uniform NAT rewrite shifts the marker's base with it, so seq mode survives the exact failure
  that ended it in the field (non-uniform normalization still defeats any client-side marker).
- **Auto-TTL**: `fake-ttl 0` learns the peer's inbound TTL from any SYN-ACK and sends the marker
  one hop short of the server â€” no traceroute needed, self-recalibrating.
- **More carriers**: wired into `wss`, `h2`, `grpc` client paths in addition to `tcp`/`tls` (the
  dial hook is shared pool machinery; on the TLS carriers the marker must be classified before the
  real ClientHello â€” it is, being injected at dial time).

Both-ends-or-client-only: **client only**, server unchanged, no wire change (unchanged verdict).
Filter countermove: non-uniform sequence normalization or full TCP state validation at the NAT
(ipid/seq sanity) â€” then no seq-mode marker passes; ttl mode remains if TTLs are not normalized.

### 1.2 Real-ClientHello re-segmentation (zapret multisplit/multidisorder family) â€” LATER (2.7.1 note: deeper blockers found)

Mechanism: instead of (or in addition to) a marker, split the *real* ClientHello into 2+ raw-crafted
TCP segments sent out of order (multidisorder) or with seq-overlap filler on the first (multisplit
with `seqovl`), so no single reassembled prefix carries a parseable SNI. Client-only on the wire
(raw injection), server-side unchanged because the kernel reassembles by sequence.

Why LATER, not BUILD this round: for the `tls`/`wss`/`h2`/`grpc` carriers the real ClientHello
flows through Go's TLS stack; implementing this requires intercepting the socket's first write
(`fragConn` exists but writes in order), taking over segmentation with raw sockets, and pinning
TTL/ack/seq per segment â€” a much larger injector than 2.7.0's, and its win over the marker is only
in regimes where the classifier *rejects* the marker but tolerates re-segmented real hellos (no
field report yet establishes that regime on the Iran path). The existing `-tls-frag` (in-order
split) already covers classifiers that only parse the first segment; re-ordering adds the case of
classifiers that reassemble until they see SNI. Add when field reports show fake-SNI blocked but
TCP still passing.

2.7.1 deeper analysis (why it stayed LATER even after a second look): zapret's implementation is
**NFQUEUE-privileged** â€” the kernel has ALREADY queued the real ClientHello when nfqws decides how
to cut it (desync.c works on the packet the kernel hands it, and `verdict` re-injects the pieces).
Our architecture is AF_PACKET (observe-only) + IPPROTO_RAW (inject-only): the real bytes go out via
the normal socket path, so the tracker can never hold the real segment back to re-segment it â€”
this would require switching the carrier's data path to NFQUEUE (root, iptables rules, per-packet
verdict latency on the pinned 30 MB/s ICMP path is irrelevant there but the complexity is real) or
a TCP_REPAIR-based send-queue rewrite (fragile). This is an architecture change, not a function â€”
hence LATER until field data demands it.

### 1.3 Domain fronting over real CDNs â€” NO (as a new feature; already available)

WatTunnel's `wss/h2/grpc + CDN + ECH + sni` path IS domain fronting in every relevant sense: the
visible SNI is the CDN front (`sni` flag), the Host/authority can differ (`host` flag), the CDN
routes by authority. Cloudflare dropped classic fronting in 2018; the surviving form (front = CDN
edge SNI, back = your own hostname behind the same CDN) is exactly what `sni` + `host` already
express. Field numbers exist (44-48 MB/s through Cloudflare). No code to add; the only residual
risk is the CDN itself filtering, which no client-side feature fixes.

### 1.4 ECH â€” already implemented (2.2.0), keep

`-ech auto` with DoH config fetch + retry + cache is shipped and tested. Under an SNI permit list,
ECH hides the real name inside the front's hello; it holds unless the filter blocks ECH itself
(dropping all ECH hellos), which is a pure-IP-level decision. Nothing to add; README already
documents the failure mode.

### 1.5 TLS-in-TLS padding â€” NO

The inner protocol is already WatTunnel's own encrypted framing (ChaCha20-Poly1305 per datagram);
an outer TLS carrier wraps it once. Adding length-concealing padding inside the session would
protect against *traffic-analysis* classification (flow-length fingerprints), not against SNI
permit lists, and costs throughput on the pinned ICMP path. Revisit only if a filter classifies by
statistical fingerprint (no evidence in the 2026 reports).

### 1.6 QUIC/HTTP3 masquerade â€” NO (for now)

Requires a full QUIC carrier (client+server, new wire encapsulation) and survives only where UDP
443 passes â€” the field record (bbs #626 era) says QUIC was fully stopped in the permit-list
window. Build only if/when field reports show UDP 443 passing while TCP is filtered.

### 1.7 Permit-list-SNI bridging (terminate real TLS to a listed name at a proxy) â€” NO

A foreign proxy with a cert for a listed Iranian name is impossible (you cannot obtain the
certificate), and a domestic proxy willing to relay is the domestic-relay problem of Â§2.4, not a
TLS trick. Rejected.

## 2. Scenario B â€” restricted routing (foreign IPs unreachable, intranet only)

First, the bcp38 reality check the task asks for: with foreign IPs unreachable, **nothing
client-side reaches the Kharej VPS at all** â€” no carrier, no marker, no re-segmentation matters.
IP-source-address rewriting as a return channel requires the *inbound* leg (packets from Kharej
bearing Iranian source addresses) to traverse Iran's ingress â€” the reverse direction of bcp38
filtering â€” and an on-path reflector willing to bounce traffic; this would be a channel through
third parties' infrastructure without their consent, fragile and unfair to those operators.
Verdict for all source-address-rewriting schemes: **NO** on ethics and on reliability (the repo's
purpose is defensive availability, not use of third parties' resources).

What remains in a true routing restriction is: channels that terminate on *domestic listed*
endpoints.

### 2.1 ICMP carrier (existing) â€” the known ceiling

The repo's own production record: ICMP echo survived the October 2026 restriction entirely (the
product exists because of it), ~30 MB/s total before an in-Iran reroute triggers, 1500-byte
payloads restored 2026-10-12. Ceiling analysis from `wat/icmp_linux.go`: one `ip4:icmp` raw socket
per process, BPF-filtered to the tunnel's ident lanes (256 lanes, sendmmsg batches via
`WAT_BATCH`), 0.2-2 % random loss repaired by the session. The ~30 MB/s ceiling is the **ICMP
rate-limit inside Iran's network** (observed as reroute-forcing), not the code: no code change can
raise it. Options measured/known: spread over multiple source IPs (requires the Iran server to own
several public IPs â€” infrastructure, not code), or per-connection pacing ceilings already in place
(`max-mbps`). No regression risk: the sim tests pin the behavior; 2.7.0 touches nothing in the ICMP
path.

### 2.2 Domestic-relay chains â€” LATER (design only)

Mechanism: a *domestic* host that still relays outward (a VPS in an Iranian datacenter with
international transit, or any user-run box inside that accepts the tunnel's carrier). This is not
a new transport â€” it is a new *placement* of the existing server role: `mode: server` runs on the
domestic box, Kharej becomes unreachable, and the domestic server bridges onward (the existing
binary already forwards only to its own 127.0.0.1:PORT; a second wattun instance chained over the
domestic carrier gives transit). Everything needed already exists in the binary (two instances
chained via `mode: client` â†’ `carrier: tcp` â†’ `mode: server` â†’ ...); what does not exist is
documentation for the chain. Recommendation: document a "domestic relay" recipe (2 instances, one
config each) rather than build new code; verify whether any Iranian datacenter still sells
outbound-transit VPSes â€” that is field work, not code.

### 2.3 DNS tunneling against listed resolvers â€” NO (for this tool)

(Continued in the next section; throughput measured 1-10 KB/s in public projects â€” far below the
ICMP carrier's 30 MB/s, and it needs a cooperating authoritative server abroad, i.e. exactly the
infrastructure a routing restriction removes.)

### 2.4 Reflection techniques â€” NO

Same verdict and reasoning as the bcp38 check above: they route through third parties' services
without consent, and their reliability on a filtered path is poor by construction.

## 3. Decision table

| # | Method | Client-only? | New infra | Field-probability | Verdict |
|---|---|---|---|---|---|
| 1.1 | Fake-SNI hardened (early+late, NAT-follow, auto-TTL, 5 carriers) | yes | none | high where seq-mode worked before | **BUILD â€” shipped 2.7.0** |
| 1.1b | Fake-SNI sum mode (in-window adjusted-checksum marker, GoodbyeDPI `--wrong-chksum` / zapret `badsum`) | yes | none | for seq-checking classifiers (ISPs usually pass adjusted checksums â€” zapret docs) | **BUILD â€” shipped 2.7.1** |
| 1.2 | Real-hello re-segmentation (multisplit/multidisorder) | yes (raw) | none | plausible, unproven on path; needs NFQUEUE architecture | LATER |
| 1.3 | Domain fronting (CDN + sni/host) | yes | none | proven (existing CDN numbers) | exists; docs only |
| 1.4 | ECH | yes | none | proven (2.2.0) | exists; keep |
| 1.5 | TLS-in-TLS padding | both ends | none | no permit-list relevance | NO |
| 1.6 | QUIC/H3 masquerade | both ends | large | UDP 443 stopped in field | NO |
| 1.7 | Listed-SNI bridging | both ends | cert impossible | â€” | NO |
| 2.1 | ICMP carrier | â€” | none | proven (this repo) | exists; ceiling is network, not code |
| 2.2 | Domestic relay chain | â€” | a domestic VPS | depends on availability | LATER (document) |
| 2.3 | DNS tunnel | both ends | foreign NS | near-zero throughput | NO |
| 2.4 | Address-rewriting / reflection | â€” | â€” | fragile, uses third parties without consent | NO |

## 4. What 2.7.0 changed, in one page

1. **Fixed the trigger bug** (the headline): `Wrap` announces the connection *after* the kernel's
   handshake finished, so the 2.6.0 state machine (which required seeing the outgoing SYN on an
   already-announced tuple) never fired. 2.7.0's tracker handles both orders:
   - *early path*: probe the stream start off the socket with TCP_REPAIR (CAP_NET_ADMIN), announce
     `(isn, known=true)`; fire on the final ACK or first data segment;
   - *late path*: probe unavailable â†’ fire anchored to the first outbound data segment only, never
     bare ACKs.
2. **NAT-follow**: SYN-ACK ack cross-check rewrites `c.synSeq = ackv - 1`.
3. **Auto-TTL**: peerTTL learned from any SYN-ACK from the peer IP; marker TTL = peerTTL âˆ’ 1; fixed
   TTL still available via `-fake-ttl N`.
4. **Carrier scope**: `attachFakeSNI` now also runs for the `ws|wss|h2|h2c|grpc` client case in
   `cmd/wattun/main.go`.
5. **Portable tracker + tests**: all state-machine logic moved to `wat/desync.go` (testable
   everywhere); Linux file only sniffs/injects. 16 tests.

## 4b. What 2.7.1 changed, in one page (this round, after the 2.7.0 research)

1. **`fake-mode: sum` (method 1.1b, BUILD)** â€” the third marker-discard variant from GoodbyeDPI
   (`--wrong-chksum`, fakepackets.c: recomputes checksums then `Checksum = htons(ntohs(Checksum) -
   1)`) and zapret (`FOOL_BADSUM`, darkmagic.c:267: `tcp->th_sum ^= 1 + random()%0xFFFF`). Chosen
   over adjusted-seq: zapret's own docs say adjusted-seq markers are also ignored by some
   classifiers, while adjusted-checksum markers fail only behind checksum-validating NATs and
   "ISPs usually pass" them. Implementation: the marker mirrors the first outbound data segment
   (in-window seq = the segment's own, correct ack), so a window-checking classifier reads it as
   the flow's real first flight; the checksum is then damaged `(checksum ^ 1) - 1` so no off-by-one
   can repair it. Server-side: kernel drops at checksum validation â€” no flow corruption by
   construction, unlike seq mode where correctness depends on the below-window arithmetic
   surviving NAT rewrites.
2. **Probe off-by-one fix** â€” `tcpStreamBase` returns SND.NXT (= ISN+1 after the handshake), but
   `Wrap` announced it as the ISN; every early-path marker would have sat one sequence number too
   high (in-window = flow-corrupting, the worst failure). Fixed in `Wrap` (`isn--` when known);
   pinned by `TestDesyncProbeIsnArithmetic`. Found while re-auditing with the kernel's own
   accounting (`net/netfilter/nf_conntrack_proto_tcp.c` window rules via GoodbyeDPI's comment).
3. **wattun-manager fake-sni support** â€” Iran wizard advanced block (name/mode/ttl asks, 2.7.0
   version gate), Advanced-settings menu (`k` key) for existing tunnels,
   `--fake-sni/--fake-mode/--fake-ttl` unattended flags, config keys emitted
   (`fake-sni`/`fake-mode`/`fake-ttl`).
4. **Domestic-relay recipe** (Â§2.2's documentation promise) written into TECHNICAL.md under the
   Fake-SNI chapter â€” two chained stock wattun instances, no new code, as researched.
5. `.gitignore` for the session's build/repair artifacts.

## 5. Next agent's queue (recommended order)

1. Field-validate 2.7.0/2.7.1 on a real Iran path (raw-socket half needs a Linux + CAP_NET_RAW
   (+ CAP_NET_ADMIN for the probe) box; see handoff): does the early path fire; does sum mode
   survive the ISP's NAT; does NAT-follow rescue a seq-affected ASN.
2. If fake-SNI gets blocked but TCP passes: Â§1.2 re-segmentation is an NFQUEUE architecture change
   â€” decide deliberately, do not bolt onto AF_PACKET (see the 2.7.1 note).
3. Push `dev`, tag `v2.7.1`, release notes (owner go-ahead; client-only update).

---

# RESEARCH-3: field status after the 2026 filter upgrades â€” what changed, what is new, what fits WatTunnel

Status: research round 3 for branch `dev` (after 2.7.0/2.7.1). Trigger: patterniha's announcement
(two new SNI-Spoofing methods tested successfully against the *updated* filter of every network he
could reach; neither is runnable on non-root Android; will ship as a standalone exe on
`127.0.0.1:40443` only if a full restriction returns while at least one Cloudflare-CDN domain stays
open). The two methods are **not public** â€” the SNI-Spoofing repo (last push 2026-04-14) still ships
only `wrong_seq`, with a `wrong_checksum` branch commented out â€” so this round researched everything
else public instead. Sources: cloned repos (SNI-Spoofing, zapret, GoodbyeDPI, Aether/PattNG,
the Iran Bale-carrier fork, MMDF) and the net4people/bbs API (issues 618, 628, 630, 640, 648, 649, 650,
653, 654, 660, 669, 673, 675, 676 with comments). Web search still unavailable; GitHub REST via
git's curl worked.

## 0. The honest answer to "are our methods already patched?"

Partly, per method:

| WatTunnel method | Field status (Oct 2026) | Source |
|---|---|---|
| fake-SNI `seq` | Not globally patched. The allowlist study found SNI filtering applied on only ~half of allowlisted source IPs, random never-registered SNIs pass freely, and no residual blocking after a reset. But the January wave defeated it on some ASNs via seq normalization. | bbs #630 |
| fake-SNI `ttl` | No field reports of TTL normalization yet; `fake-ttl: 0` auto-calibration keeps it viable. | â€” |
| fake-SNI `sum` (2.7.1) | Unpatched by construction: adjusted-checksum markers fail only behind checksum-validating NATs (rare on Iranian ISPs per zapret's field notes). | zapret docs |
| `tls-frag` (real-hello fragmentation) | **No longer working on the paths where the upgrade deployed**: "GFW drops all fragmented tlshello packets" (#640), and the DPI now reassembles TCP fragments to extract SNI from VLESS/WS+CDN setups, with DNS hijack to 10.10.34.34 and resets after (#628). Contested: another reporter still sees fragmentation working ("it would cost them too much to upgrade everywhere") â€” consistent with the #630 finding that enforcement is per-IP/per-segment, not global. | #640, #628 + comments |
| ICMP carrier | Still the backbone: only ICMP passes on several routes since early Oct 2026; 1500 B restored; ~50k pps / ~30 MB/s ceiling with volume-triggered reroute â€” network limits, not code. | #676 |
| CDN + ECH (`wss/h2/grpc`) | Works where CDN is reachable: 44â€“48 MB/s down, 82 up; every non-ECH variant failed. | #676 |

So: our flow-marker family is alive but living on borrowed time in the parts that depend on the
filter NOT validating fields; the parts that depend on the filter not seeing the real bytes at all
(fragmentation) are being actively upgraded. Anything new should assume **full TCP reassembly,
SNI extraction, checksum/window validation, and behavioral (lifetime/volume) classification** at
the DPI â€” because that is what the Geedge source leak confirms real products do (#653).

## 1. What everyone else is doing right now (the landscape)

### 1.1 Ride a whitelisted SERVICE, not a synthetic hello â€” WebRTC carrier tunnels (the strongest genuinely-new idea)
- **bbs #618** ("Tunneling IP traffic through whitelisted WebRTC carriers"): under IP/SNI/CIDR
  permit lists, transport-level mimicry loses; traffic must literally BE a whitelisted service.
  Domestic video-call platforms (Bale Meet in Iran, VK/Telemost in Russia) are SFU-mediated
  encrypted media the operator trusts. Two peers run headless Pion; the carrier rides either an
  SCTP DataChannel or a synthetic VP8 track (no real encoder: two hardcoded frame prefixes + epoch
  + nonce + AEAD ciphertext).
- **Implementations**: the Russia tool by kulikov0 and its Iran fork (repo names avoided here deliberately)
  (Bale fork; Android/iOS/Desktop via VpnService + tun2socks; no root needed â€” this is exactly the
  gap patterniha complained about). ~6.5 Mbps ceiling per VP8 track (fpsÃ—batchÃ—1126 B), doubled
  with a screenshare track; DC mode lighter but slower. SFU congestion control limits pushing past
  per-track rates (it stalls, not drops). Bale's SFU reorders frames enough that the carrier
  needed a 16-frame reorder buffer to not collapse under TCP.
- **Speed/reliability verdict**: ~6.5â€“13 Mbps â€” far below WatTunnel's ICMP 30 MB/s, and dependent
  on a third party's SFU. But it is the only public method that survives a *complete* SNI/IP
  permit list while staying non-root-Android-viable, and it is indistinguishable by construction
  (it is a video call to a whitelisted domestic service).

### 1.2 Serverless configs (no server at all) â€” patterniha's `Serverless-for-Iran` (1269â˜…)
Xray-core â‰¥ 26.6.27 client configs; works because under the 2026 permit list many major foreign
services (github, openai, microsoft, google...) are reachable DIRECTLY from Iran. The config:
- routes those services direct (fakedns + geosite lists);
- `tcp-fragment` 1-byte splits (maxSplit 201) and tlshello fragments at byte offsets 6/98/1 and
  0/104/1 (two variants A/B) for everything TLS;
- 24 Ã— 1200â€“1230-byte random UDP "noise" packets to keep UDP paths responsive;
- blocks QUIC/UDP-443 and the DNS-hijack IP 10.10.34.34; happy-eyeballs with **IPv6 prioritized**
  (IPv6 is measurably less filtered on mobile).
Speed = line speed for the services that pass; zero infrastructure. Limitation: it is a routing
trick, not a tunnel â€” no arbitrary foreign site unless it is direct-reachable or frontable.

### 1.3 MMDF â€” client-side MITM + domain fronting (patterniha; merged into Xray-core via issue 4348)
No server: the client performs a local TLS intercept with a locally-installed root cert ("Instant
Certificate"), reads the real Host, then re-originates the request with a FRONT SNI toward CDNs
that still permit fronting (Google, Fastly, Meta; NOT Cloudflare/Cloudfront/Arvan). Declared
"unblockable except by IP block" and it runs on non-root Android **browsers only** (user-cert
limitation â€” plausibly one of patterniha's two new exe methods is the same family with raw
sockets). Big caveats: upstream cert validation "not performed yet" (a real intercept risk by
design), works only for fronting-friendly services, and trusting a root cert is a security
tradeoff WatTunnel should never make silently.

### 1.4 Aether / PattNG (patterniha's Android answer; his actual non-root path)
Rust WARP-class client: **MASQUE over HTTP/3 and HTTP/2** with uTLS-style ClientHello
fragmentation on the H2 leg, `--gool` (WireGuard inside MASQUE), `--mim` (MASQUE inside MASQUE),
"noize" filler-packet profiles (firewall/gfw/aggressive â€” filler before handshake, between I1,
after handshake, 1â€“12 ms intervals), automatic endpoint discovery with end-to-end data-plane
validation, Termux installer for non-root Android. It powers PattNG (pushed daily). This is the
same family as our `wss/h2 + ECH` path (44â€“82 MB/s measured) plus discovery and nesting.

### 1.5 Mimicry pools with lifetime budgets â€” Hedioum Pool Tunnel (#649)
Go tunnel from inside Iran; the sharpest operational insight in the whole round: after raw volume,
**protocol Ã— connection lifetime is the strongest real-world tell** â€” "a TLS flow held open for
hours moving tens of GB is anomalous regardless of a perfect handshake". Their countermeasure:
SSH as the long-lived backbone, every other persona (TLS/SMTP/IMAP/DirectAdmin) lives 5â€“60
min / 1â€“5 GB then churns; per-install fluctuating persona distribution; uTLS Chrome hello; probes
answered by real decoy services; Let's Encrypt certs when a domain exists.

### 1.6 Xray `finalmask` â€” the industrialized masking framework (v25.10.15 â†’ 26.10, 62+ issues)
Xray turned every classic mask into a composable layer under `finalmask`: `xdns` (DNS carrier via
mKCP, client MTU ~130), **`xicmp`** (raw-socket ICMP echo carrier, needs root/CAP_NET_RAW, no MTU
limit since IP layer fragments, developer's own caveat: "still a toy â€” length alone can limit
it"; kernel echo must be silenced like ours), `header-*` (dtls/srtp/utp/wechat/wireguard
byte-prefix masks, 4â€“13 B overhead), `noise` (UDP filler, the in-stack cousin of our marker),
`fragment`, `sudoku`, `realm` (UDP hole punching), Salamander, Lua-scriptable masks. Also QUIC SNI
filtering is now established in Russia since 2023 (#654) â€” QUIC Initial is decryptable by design,
so QUIC is not a safe harbor where that hardware deploys.

### 1.7 Russia's mobile permit list as the mirror (#650, + comments)
Same architecture, instructive failures: enforcement varies per base station and per radio
channel (same phone, same minute, different cell â†’ different policy); hardcoded foreign DNS
(8.8.8.8) breaks even listed sites; public CIDR allowlists are wrong in both directions ("the only
check I trust is a SIM, on the day, against the specific /24" â€” `vadim-tolmachev/allowlist-probe`);
700+ reserved floating IPs across five cloud regions produced zero known-permitted /24s. Lesson
for Iran: per-segment enforcement is the norm, so per-connection adaptive testing beats any static
allowlist; WatTunnel's `auto` carrier test and manager's variant ranking are the right shape.

### 1.8 Two papers worth knowing
- **#653 Geedge/TSG source leak (USENIX Sec '26)**: first public build-and-run of a real national
  filter; parseable protocol list and rule format extracted; usable to test marker-packet realism
  offline. (Iran is a known customer region for such vendors.)
- **#669 Espejismo** (look-like-nothing framing with masked lengths, time-slotted keys, silent
  reject): commenters restate the USENIX '23 GFW result â€” fully-encrypted "nothing" protocols get
  classified and stopped; impersonating real TLS beats looking like nothing. Confirms our
  carriers' direction.

## 2. What WatTunnel should actually do (ranked, with speed/reliability expectations)

1. **Adopt connection-lifetime/volume churn in the pool layer (cheap, high value, zero wire
   change).** Mirror Hedioum's budgets: recycle a pool connection after N minutes / N GB (client-
   side only, e.g. `pool-rotate: 30m/4GB`), staggered per connection, so no flow looks like a
   months-long TLS pipe. Directly addresses the #628 pattern (throughput → probe → block
   domain+IP) and #649's field rule. Speed cost ≈ 0 (redial at a chosen moment). This is the best
   speed-per-effort item on the list. **Implemented in 2.8.0**: `pool-rotate` (time budget only,
   byte axis reserved in the API), ±40 % jitter per connection, re-rolled every recycle.
2. **A Bale/WebRTC-style carrier as the permit-list-proof fallback (new code, medium-large).** Not
   for speed (~6.5–13 Mbps) but for the regime nothing else survives: carry the session's
   datagrams over a Bale Meet (or other whitelisted SFU) VP8/DataChannel via headless Pion, as a
   `carrier: bale` option client-side only. Android viability via VpnService+tun2socks is solved
   by the fork we'd learn from. Mark clearly: third-party dependency, terms-of-service and
   reliability caveats, and it needs the SFU's API surface (join-token-derived keys, no extra
   auth channel).
3. **Keep hardening fake-SNI, expect the countermove to be behavioral, not packet-shaped.** The
   seq/sum/ttl modes hold while the filter checks fields; the #628 pattern suggests pairing
   fake-SNI with item 1's churn and with `sni`+`fp` on the real hello (already supported) so the
   real flow also looks like TLS-to-allowed-site end-to-end. **2.8.0 adds `fake-mode: seqsum`**
   (both markers per connection, ~1 ms apart) and **fixes the sum-marker checksum damage**: the
   2.7.1 formula `(checksum ^ 1) - 1` is an identity for every even checksum, so ~half of the
   sum-mode markers shipped with a fully valid checksum and the server would have accepted their
   payload as real data (flow corruption). Now `checksum - 1` with a valid-fold guard.
4. **Do NOT invest in more fragmentation of the real ClientHello.** #640/#628 show the upgraded
   DPI reassembles; our `tls-frag` stays as-is for un-upgraded segments.
5. **QUIC/H3: still NO** (blocked in the field; QUIC SNI filtering exists in Russia and is
   trivially portable â€” Initial is decryptable by design).
6. **"Look-like-nothing" framing changes: NO** (USENIX '23 + #669 consensus).
7. **Residential-source relays / Starlink sharing: NO on safety grounds** (#675 documents that
   possessing/sharing Starlink access in Iran can carry the death penalty; domestic relay chains
   remain the documented, consented alternative in TECHNICAL.md).

## 3. What patterniha's two unreleased methods probably are (and why we should not chase them)

His statement + repo give three constraints: methods are IP/TCP-header manipulation (the repo's
self-description), they need raw sockets (hence no non-root Android), and one ships as a local
exe with a SOCKS/port listener (127.0.0.1:40443). The commented-out `wrong_checksum` branch (with
`ipv4.ident + 1` next to it) and zapret's variant taxonomy bound the plausible space: variants of
checksum/seq/ident/IP-fragment variants on the marker, likely combined (two markers per
connection, the GoodbyeDPI `--wrong-seq + --wrong-chksum` double-marker pattern, which 2.8.0's
`fake-mode: seqsum` implements). If both were
"tested successfully against the updated filter of every network", the differentiator is likely
**combining variants and IP-layer fragmentation of the marker itself**. One correction to an
earlier draft of this section: fragmenting the marker is NOT free — if the filter's rule is
"fragmented TLS hello → treat the flow as blocked" (the #640 behavior), a fragmented marker tags
the very flow it was meant to save; gate it behind a path probe and default off. The rest stands:
the marker is discarded
by the server anyway, so fragmenting it defeats DPI marker-reassembly of the fake itself. That is
a cheap experiment worth a `fake-mode`/`fake-frag` knob in our injector (send the marker as 2â€“3
IP fragments), but it is a variant of what we have, not a new class; treat as item 3's optional
extension after field tests confirm fake-SNI is being read-then-dropped (the failure signature
would be: the filter classifies the flow as blocked despite a valid seq/ttl/sum marker).

## 4. Bottom line

- The upgrade wave defeats **fragmentation of real hellos** and **behavioral anomalies** (lifetime,
  volume, throughput-triggered probing), not yet **field-variant markers** nor **ICMP** nor
  **CDN+ECH**.
- The only genuinely new class with real traction is **riding a whitelisted service** (WebRTC/
  Bale), at ~6.5â€“13 Mbps â€” an availability fallback, not a speed leader.
- The best speed/reliability plays available to WatTunnel are: keep ICMP (30 MB/s) + CDN/ECH
  (44â€“82 MB/s) as the primary paths, add **connection churn** to defeat behavioral classification,
  optionally add **marker IP-fragmentation**, and add a **Bale carrier** as the last-resort permit-
  list survival mode. None of these requires breaking wire compatibility; 1 and 3 are small diffs;
  2 is the only large one and should be gated on field evidence that ICMP+CDN paths died for a user.

â€” Written by the round-3 research pass (sources: cloned repos listed in Â§0; bbs issue numbers cited
inline; all external claims carry their source; no live web was available, GitHub API via git-curl).
