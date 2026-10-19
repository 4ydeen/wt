# RESEARCH-2: next methods for whitelisting and blackout scenarios (WatTunnel 2.7.0)

Status: research for branch `dev`, following 2.6.0's fake-SNI desync (see `FAKE-SNI-DESIGN.md`,
`AGENT-HANDOFF-CHANGES.md`). Companion deliverable to the 2.7.0 implementation commit. Written for
engineers (human or AI) continuing this work. The project's purpose is keeping internet access
alive for its users during network restrictions; everything below is published, public
transport-layer engineering, same family as the public projects it derives from.

## 0. Method and sources

Reference projects were cloned and their sources read (not docs-only reverse-engineering):

- **patterniha/SNI-Spoofing** (`fake_tcp.py`, `main.py`, cloned) — WinDivert-based relay: registers
  each outgoing connection in a dict, tracks outbound SYN → inbound SYN-ACK (with strict ISN/ack
  cross-checks) → outbound final ACK, then mutates a *copy* of that final ACK into the fake
  (`packet.tcp.seq = syn_seq + 1 − len(fake_data)`, PSH set, ip.ident +1) and re-injects it.
  Wrong-seq only — no TTL mode in the shipped code (BYPASS_METHOD is hardcoded `"wrong_seq"`). The
  relay waits for the server's dup-ACK of the fake (`fake_data_ack_recv`) before attaching the
  user's socket. WatTunnel 2.6.0 modelled exactly this state machine.
- **zapret** (bol-van/zapret, `nfq/desync.c` 3504 lines, cloned) — the most complete public
  taxonomy of TCP desyncs: `fake`, `fakeknown`, `rst`, `rstack`, `syndata`, `disorder`
  (fakeddisorder), `fakedsplit`, `multisplit`, `multidisorder` (disorder2), `hostfakesplit`,
  `ipfrag2`, plus UDP `udplen`/`tamper`. Key implementation facts (from desync.c):
  - `DESYNC_MULTISPLIT` splits the payload at configurable positions and sends each part as its own
    raw-crafted segment; `seqovl` prepends junk to the first part below its seq so the DPI's
    reassembler desyncs while the real server (which validates windows) accepts only the true
    bytes (desync.c:2252-2328).
  - `DESYNC_MULTIDISORDER` sends the parts **in reverse order** (desync.c:2342: `for (i =
    multisplit_count - 1, to = len_payload; i >= -1; i--)`) so a DPI that reassembles in arrival
    order reads a scrambled stream; the server reassembles by sequence and is unaffected.
  - `DESYNC_FAKEDDISORDER` interleaves fake (junk-pattern, fake TTL/checksum flags) and real
    segments in a configurable ordering (desync.c:2395-2528): fake-part-2 → real-part-2 → fake-1 →
    real-1 (or variations), so the first data the DPI reassembles is junk, and the real ClientHello
    bytes never arrive contiguously.
  - `hostfakesplit` splits around the hostname and sends a fake hostname segment in between.
  - Fake packets use a **fixed 680-byte ClientHello template** (SNI `www.microsoft.com`,
    desync.c:20) — zapret accepts the fingerprint risk in exchange for realism; we deliberately
    keep per-build randomness instead (2.6.0 decision, unchanged).
- **GoodbyeDPI** (ValdikSS, cloned) — same family, Windows-focused: fake packets with wrong seq/ack
  combos, TTL tricks, `Host:` stripping/replacement for HTTP, periodic TCP fragmentation. Confirms
  the same mechanism family; nothing beyond zapret's set.
- **net4people/bbs #626** (January 2026 whitelisting) — referenced through the repo's own field
  notes and the 2.6.0 handoff (live fetch of the BBS was not possible from this environment; the
  facts below that trace to #626 come from the repo's records): allowlisted-SNI desync worked for
  ~4 days on some ISPs, then ISP NATs began normalizing sequence numbers before the DPI, killing
  seq mode; ttl mode survived where hop counts were stable; ICMP/QUIC/plain-UDP tunnels were fully
  blocked in that window.

Environment note: web_search/web_fetch were unavailable this session (API auth + DNS sink), so all
new claims are sourced from cloned sources listed above and from this repo's own field records;
items marked *unverified* rest on the prior agent's handoff rather than a fresh fetch.

## 1. Scenario A — whitelisting (allowlisted SNI/IP only)

Ranking criteria: probability of working per field reports, deployability on the existing
Kharej-VPS + Iran-client topology, new infrastructure needed. Verdicts: **BUILD** (implemented in
2.7.0), LATER (recommended next round), NO (rejected).

### 1.1 Fake-SNI desync hardening — BUILD (shipped in 2.7.0)

While re-deriving the trigger mechanics from SNI-Spoofing and zapret, one **critical 2.6.0 bug**
surfaced: the sniffer only tracked handshakes for 4-tuples already announced by `Wrap`, but `Wrap`
runs *after* `dial()` returns — the kernel's SYN, and often the SYN-ACK and final ACK, are on the
wire before any announcement. The state machine's first two transitions therefore never matched on
a normal dial, the fake never fired, and every connection silently degraded to the 2 s
unclassified fallback. 2.7.0 fixes this and hardens the method:

- **Portable tracker** (`wat/desync.go`): the handshake state machine is OS-independent and fed
  raw IPv4 packets; the Linux file only sniffs and injects. Fully unit-tested on any OS (16 tests).
- **Two trigger paths** (after zapret's zero-stage/second-stage split):
  - *early*: the stream start is probed off the socket (TCP_REPAIR + TCP_REPAIR_QUEUE + QUEUE_SEQ —
    the only kernel interface exposing a socket's sequence numbers), so the fake fires on the
    handshake's final ACK or the first data segment, whichever comes first, even if the sniffer
    missed the SYN/SYN-ACK. Needs CAP_NET_ADMIN for the probe; falls back gracefully.
  - *late*: probe unavailable → the fake is anchored to the first outbound **data** segment
    (same-segment-bundle desync; the fake rides the packet the DPI is about to parse).
- **NAT-sequence follow**: the tracker cross-checks the SYN-ACK's ack against the known ISN; a
  uniform NAT rewrite shifts the fake's base with it, so seq mode survives the exact failure that
  killed it in the field (non-uniform normalization still defeats any client-side fake).
- **Auto-TTL**: `fake-ttl 0` learns the peer's inbound TTL from any SYN-ACK and sends the fake one
  hop short of the server — no traceroute needed, self-recalibrating.
- **More carriers**: wired into `wss`, `h2`, `grpc` client paths in addition to `tcp`/`tls` (the
  dial hook is shared pool machinery; on the TLS carriers the fake must be classified before the
  real ClientHello — it is, being injected at dial time).

Both-ends-or-client-only: **client only**, server unchanged, no wire change (unchanged verdict).
Censor countermove: non-uniform sequence normalization or full TCP state validation at the NAT
(ipid/seq sanity) — then no seq-mode fake passes; ttl mode remains if TTLs are not normalized.

### 1.2 Real-ClientHello disordering (zapret multisplit/multidisorder family) — LATER

Mechanism: instead of (or in addition to) a fake, split the *real* ClientHello into 2+ raw-crafted
TCP segments sent out of order (multidisorder) or with seq-overlap junk on the first (multisplit
with `seqovl`), so no single reassembled prefix carries a parseable SNI. Client-only on the wire
(raw injection), server-side unchanged because the kernel reassembles by sequence.

Why LATER, not BUILD this round: for the `tls`/`wss`/`h2`/`grpc` carriers the real ClientHello
flows through Go's TLS stack; implementing disorder requires intercepting the socket's first write
(`fragConn` exists but writes in order), taking over segmentation with raw sockets, and pinning
TTL/ack/seq per segment — a much larger injector than 2.7.0's, and its win over the fake is only in
regimes where the censor *rejects* the fake but tolerates fragmented real hellos (no field report
yet establishes that regime on the Iran path). The existing `-tls-frag` (in-order split) already
covers DPIs that only parse the first segment; disorder adds the case of DPIs that reassemble
until they see SNI. Add when field reports show fake-SNI blocked but TCP still passing.

### 1.3 Domain fronting over real CDNs — NO (as a new feature; already available)

WatTunnel's `wss/h2/grpc + CDN + ECH + sni` path IS domain fronting in every relevant sense: the
visible SNI is the CDN front (`sni` flag), the Host/authority can differ (`host` flag), the CDN
routes by authority. Cloudflare dropped classic fronting in 2018; the surviving form (front = CDN
edge SNI, back = your own hostname behind the same CDN) is exactly what `sni` + `host` already
express. Field numbers exist (44-48 MB/s through Cloudflare). No code to add; the only residual
risk is the CDN itself filtering, which no client-side feature fixes.

### 1.4 ECH — already implemented (2.2.0), keep

`-ech auto` with DoH config fetch + retry + cache is shipped and tested. Under an SNI allowlist,
ECH hides the real name inside the front's hello; it dies only if the censor blocks ECH itself
(dropping all ECH hellos), which is a pure-IP-level kill. Nothing to add; README already documents
the failure mode.

### 1.5 TLS-in-TLS padding — NO

The inner protocol is already WatTunnel's own encrypted framing (ChaCha20-Poly1305 per datagram);
an outer TLS carrier wraps it once. Adding length-concealing padding inside the session would
protect against *traffic-analysis* classification (flow-length fingerprints), not against SNI
allowlisting, and costs throughput on the pinned ICMP path. Revisit only if a censor classifies by
statistical fingerprint (no evidence in the 2026 reports).

### 1.6 QUIC/HTTP3 masquerade — NO (for now)

Requires a full QUIC carrier (client+server, new wire encapsulation) and survives only where UDP
443 passes — the field record (bbs #626 era) says QUIC was fully blocked in the whitelisting
window. Build only if/when field reports show UDP 443 passing while TCP is filtered.

### 1.7 Allowlist-SNI bridging (terminate real TLS to allowlisted name at a proxy) — NO

A foreign proxy with a cert for an allowlisted Iranian name is impossible (you cannot obtain the
certificate), and a domestic proxy willing to relay is the domestic-relay problem of §2.4, not a
TLS trick. Rejected.

## 2. Scenario B — full blackout (foreign IPs unreachable, intranet only)

First, the bcp38 reality check the task asks for: with foreign IPs unreachable, **nothing
client-side reaches the Kharej VPS at all** — no carrier, no spoofing, no fragmentation matters.
IP-source-spoofing as a return channel requires the *inbound* leg (spoofed packets from Kharej
bearing Iranian source IPs) to traverse Iran's ingress — the reverse direction of bcp38 filtering
— and an on-path reflector willing to bounce traffic; this is a covert third-party-abuse channel,
fragile and abusive of others' services. Verdict for all IP-spoofing schemes: **NO** on ethics and
on reliability (the repo's purpose is defensive availability, not abuse of third parties).

What remains in a true blackout is: channels that terminate on *domestic allowlisted* endpoints.

### 2.1 ICMP carrier (existing) — the known ceiling

The repo's own production record: ICMP echo survived the October 2026 restriction entirely (the
product exists because of it), ~30 MB/s total before an in-Iran reroute triggers, 1500-byte
payloads restored 2026-10-12. Ceiling analysis from `wat/icmp_linux.go`: one `ip4:icmp` raw socket
per process, BPF-filtered to the tunnel's ident lanes (256 lanes, sendmmsg batches via
`WAT_BATCH`), 0.2-2 % random loss repaired by the session. The ~30 MB/s ceiling is the **ICMP
rate-limit inside Iran's network** (observed as reroute-forcing), not the code: no code change can
raise it. Options measured/known: spread over multiple source IPs (requires the Iran server to own
several public IPs — infrastructure, not code), or per-connection pacing ceilings already in place
(`max-mbps`). No regression risk: the sim tests pin the behavior; 2.7.0 touches nothing in the ICMP
path.

### 2.2 Domestic-relay chains — LATER (design only)

Mechanism: an allowlisted *domestic* host that still proxies outward (a VPS in an Iranian datacenter
with international transit, or any user-run box inside that accepts the tunnel's carrier). This is
not a new transport — it is a new *placement* of the existing server role: `mode: server` runs on
the domestic box, Kharej becomes unreachable, and the domestic server bridges onward (the existing
binary already forwards only to its own 127.0.0.1:PORT; a second wattun instance chained over the
domestic carrier gives transit). Everything needed already exists in the binary (two instances
chained via `mode: client` → `carrier: tcp` → `mode: server` → ...); what does not exist is
documentation for the chain. Recommendation: document a "domestic relay" recipe (2 instances, one
config each) rather than build new code; verify whether any Iranian datacenter still sells
outbound-transit VPSes — that is field work, not code.

### 2.3 DNS tunneling against allowlisted resolvers — NO (for this tool)

Mechanism: encode session datagrams in TXT/NULL queries to a resolver that forwards to an
authoritative server abroad. Even when the resolver is domestic and allowlisted: (a) the domestic
resolver must be configured to *recurse* for our domain — during whitelisting/blackout the
allowlist typically covers the resolver's own service, not arbitrary recursion to foreign
authorities; (b) throughput ceiling is ~1-10 KB/s per resolver (query rate limits, ~200 B payload
per query, RTT-bound), i.e. 3-4 orders of magnitude below the ICMP carrier's 30 MB/s; (c) it needs
controlling a foreign authoritative DNS server — new infrastructure the task says to minimize.
The repo's precedence (ICMP at 30 MB/s) makes DNS strictly worse on every axis. Verdict: NO; only
worth revisiting as an emergency signaling channel (not data) if everything else dies — and even
then a few bytes of "try X" fits through existing side channels.

### 2.4 Reflected/carrier channels off domestic anycast services — NO

Bouncing off domestic CDNs/anycast (e.g. abusing an Iranian CDN's cache-miss to originate foreign
requests) is either third-party abuse (same verdict as IP spoofing) or already covered by §2.2
when the domestic box is one's own.

## 3. Decision table

| # | Method | Client-only? | New infra | Field-probability | Verdict |
|---|---|---|---|---|---|
| 1.1 | Fake-SNI hardened (early+late, NAT-follow, auto-TTL, 5 carriers) | yes | none | high where seq-mode worked before | **BUILD — shipped 2.7.0** |
| 1.2 | Real-hello disorder (multisplit/multidisorder) | yes (raw) | none | plausible, unproven on path | LATER |
| 1.3 | Domain fronting (CDN + sni/host) | yes | none | proven (existing CDN numbers) | exists; docs only |
| 1.4 | ECH | yes | none | proven (2.2.0) | exists; keep |
| 1.5 | TLS-in-TLS padding | both ends | none | no whitelisting relevance | NO |
| 1.6 | QUIC/H3 masquerade | both ends | large | UDP 443 blocked in field | NO |
| 1.7 | Allowlist-SNI bridging | both ends | cert impossible | — | NO |
| 2.1 | ICMP carrier | — | none | proven (this repo) | exists; ceiling is network, not code |
| 2.2 | Domestic relay chain | — | a domestic VPS | depends on availability | LATER (document) |
| 2.3 | DNS tunnel | both ends | foreign NS | near-zero throughput | NO |
| 2.4 | IP spoofing / reflection | — | — | fragile, abusive | NO |

## 4. What 2.7.0 changed, in one page

- `wat/desync.go` rewritten: portable `desyncTracker` (state machine + fake packet builder +
  config validation, testable everywhere), early/late trigger paths, NAT-sequence follow,
  auto-TTL calibration from peer SYN-ACKs. `fakePacket()` and `parseEthIPv4()` extracted as pure
  functions; `htons/csum/tcpChecksum/FakeClientHello/parseSNIOf/desyncPeerIP` unchanged.
- `wat/desync_linux.go`: sniffer + raw sender over the tracker; `tcpStreamBase` probes SND.NXT via
  TCP_REPAIR/TCP_REPAIR_QUEUE/TCP_QUEUE_SEQ (needs CAP_NET_ADMIN, falls back to the late path);
  `Wrap` announces with probe result, abandons on timeout; fake fires exactly once per connection.
- `wat/desync_other.go`: same startup-failure pattern, plus shared validation so error messages
  match on every OS.
- `wat/desync_test.go`: 5 existing tests kept + 11 new (16 total) pinning: early fire before data,
  early fire on first data, late fire, late no-fire on bare ACKs, NAT rewrite shift, TTL
  calibration (fresh + pre-learned + not-yet), fixed TTL, one-fake-per-conn, unannounced-conn
  ignore, fake packet round-trip (checksum + parse), abandon/close, non-IPv4 rejection.
- `cmd/wattun/main.go`: fake-SNI wired into wss/h2/h2c/grpc client cases; flag help updated.
- Docs/versions: TECHNICAL.md (carrier scope, auto-TTL, 2.7.0 history), READMEs (badge v2.7.0 +
  intro), `wat/version.go` → 2.7.0. Wire format unchanged; server unchanged; ICMP path untouched.

## 5. Next agent's queue (recommended order)

1. Field-validate 2.7.0's early/late triggers on a real Iran path (the raw-socket half still needs
   a Linux + CAP_NET_RAW box; see handoff).
2. If fake-SNI gets blocked but TCP passes: implement §1.2 disorder (portable split-point
   resolver + segment builder fits the 2.7.0 tracker; the `send` hook already abstracts injection).
3. If blackout returns: write the domestic-relay recipe (§2.2) into TECHNICAL.md after field
   checking domestic VPS availability; no code needed.
