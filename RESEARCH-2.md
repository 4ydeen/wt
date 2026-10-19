# RESEARCH-2: next steps for the permit-list and restricted-routing scenarios (WatTunnel 2.7.0/2.7.1)

Status: research for branch `dev`, following 2.6.0's fake-SNI flow marker (see
`FAKE-SNI-DESIGN.md`, `AGENT-HANDOFF-CHANGES.md`). Companion deliverable to the 2.7.0
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
