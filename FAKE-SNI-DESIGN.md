# Fake-SNI desync: design document (WatTunnel 2.6.0)

Status: implemented on branch `dev`, commit `bf92665`. Client-side only. This document is the full
technical reference for the method, written for engineers (human or AI-assisted) continuing this work.
Everything described here is published technique — see the references at the end — applied to this
codebase. The project's purpose is keeping internet access alive for its users during network
restrictions; the method below is standard transport-layer engineering, same family as the public
projects it derives from.

## 1. The problem it solves

During a whitelisting regime, the middlebox on the path classifies every new TCP flow by parsing the
first application-data bytes (for TLS, the ClientHello's server_name / SNI field) and drops flows whose
destination name is not on the allowlist. Encrypted tunnels to a foreign VPS have no allowlisted name,
so every carrier that looks like "TLS to an unknown host" is dropped, regardless of the payload.

Key observation from the field (Iran, January 2026, net4people/bbs #626): the classifier reassembles
the TCP flow and reads bytes **without validating TCP sequence-number windows**. It also runs **before**
any NAT that would rewrite sequence numbers only on some ISP paths. That mismatch — a stateful parser
without state validation — is what this method exploits. This is a textbook DPI-desync technique,
documented publicly since at least 2015 and shipped in widely used open-source tools (references below).

## 2. The method in one paragraph

Complete a normal TCP handshake to our own server (the censor sees a benign SYN/SYN-ACK/ACK exchange).
Immediately after the handshake, send **one raw packet** that carries a fake TLS ClientHello whose SNI
is an allowlisted domestic name (e.g. `mci.ir`). The fake is crafted so that **our server discards it**
but **the censor's reassembler accepts it**:

- **seq mode**: the fake's sequence number is set below the stream's first byte, so the real server's
  kernel treats it as an already-acknowledged old duplicate and dup-ACKs it away. A reassembler that
  doesn't check windows prepends it to the flow anyway.
- **ttl mode**: the fake is sent with a small TTL calibrated to expire exactly at the censor's hop, so
  it never reaches the real server at all.

The censor parses the fake ClientHello, sees the allowlisted SNI, and marks the whole flow as
"TLS to an allowlisted site". Every subsequent packet on that connection — which is actually the
tunnel's own encrypted frames — passes as TLS application data. The real server never received the
fake, so its TLS state machine never started; the connection carries WatTunnel frames from byte one.

## 3. Why the two endpoints behave differently

### 3.1 The real server (correct TCP stack)

Linux's receiver tracks `rcv_nxt`. After the handshake, `rcv_nxt = ISN_client + 1`. The fake's seq is
`ISN + 1 − len(fake)` — a range that lies entirely *before* `rcv_nxt`, i.e. already-acknowledged
territory. RFC 793 behaviour: drop silently (optionally dup-ACK). No data reaches the application, no
TLS parser runs, no RST. The fake is invisible to our server by construction.

In ttl mode the fake dies at an intermediate hop (TTL reaches 0 before the server), so the server sees
nothing at all — even more robust, but requires knowing/approximating the hop count to the censor.

### 3.2 The censor (reassembly without window checks)

The DPI holds per-flow state keyed by the 4-tuple and reassembles segments in sequence order — or
simply concatenates what arrives — to parse the first flight of application data. It does not maintain
a receiver window or drop segments below the left edge, because it must tolerate out-of-order delivery,
retransmits, and mid-flow attachment. When the fake arrives carrying an SNI, the classifier extracts
it, matches the allowlist, and tags the flow as permitted. From then on the flow is fast-pathed; the
tunnel's encrypted frames are never parsed as TLS again (they're after the classification point, and
they don't need to parse — the flow is already allowed).

## 4. Anatomy of the fake ClientHello (`wat/desync.go`, `FakeClientHello`)

A minimal but fully RFC-conformant TLS 1.2-format ClientHello, ~90–110 bytes depending on SNI length:

```
16 03 01 LL LL            TLS record: handshake, version 1.0 (as real clients send in the clear), length
01 00 00 LL               handshake: ClientHello, 3-byte length
03 03                      client_version 1.2
<32 random bytes>          from crypto/rand — two builds never identical, no fixed fingerprint
00                         session_id length 0
00 04 C0 2B C0 23          2 cipher suites: ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-ECDSA-AES128-SHA256
01 00                      compression methods: null
EE EE                      extensions length
  00 00 .. ..              server_name: list_len, type host_name, name_len, <SNI bytes>
  00 0A 00 06 00 04 00 1D 00 18   supported_groups: x25519, secp256r1
  00 0D 00 04 00 02 04 03  signature_algorithms: ecdsa_secp256r1_sha256
```

Design decisions:

- **Version `03 01` in the record header, `03 03` in the body** — this is what every real TLS 1.2/1.3
  client sends; a parser that sees `03 03` in the record header pre-handshake is a fingerprint anomaly.
- **Randomness per build** — the 32-byte random comes from `crypto/rand`. A fixed template would itself
  be a signature a future classifier could block on.
- **Why these extensions** — the SNI alone parses fine, but classifiers increasingly validate structure
  (cipher list plausibility, key-exchange groups, signature algorithms). supported_groups and
  signature_algorithms make the hello survive a stricter parser; the test suite pins this by feeding the
  fake to Go's own `crypto/tls` server and asserting it passes record/hello parsing (see §8).
- **ECDSA-only ciphers** — two suites instead of fifteen keeps the packet small (single TCP segment even
  with headers, no IP fragmentation risk) while remaining a valid offer.

## 5. The injector state machine (`wat/desync_linux.go`)

The kernel does not export a socket's ISN or SND.NXT (checked: `x/sys/unix.TCPInfo` has no such field,
and the kernel's `tcp_info` struct genuinely doesn't report it). So the injector learns the handshake
parameters the same way the reference tool does: by sniffing the wire.

One AF_PACKET `SOCK_RAW` socket on `ETH_P_ALL` per client process; a single reader goroutine (`loop`)
parses every ethernet frame and advances a per-4-tuple state machine:

| event (on the wire) | condition | action |
|---|---|---|
| outgoing SYN | SYN, no ACK, no payload, 4-tuple pre-announced by `Wrap` | record `synSeq` = ISN |
| inbound SYN-ACK | SYN+ACK, no payload, matches reversed tuple | record `synAckSeq`, `synAckAck` (= our ISN+1) |
| outgoing final ACK | ACK, no SYN, no payload, ack field == `synAckSeq+1` | fire the fake, release `Wrap` |

The final-ACK test (`ack == synAckSeq+1`) is what distinguishes the handshake's third packet from any
later bare ACK on the connection — later ACKs acknowledge more data, so they never equal `synAckSeq+1`.

`Wrap` (called from the pool's dial hook, after the kernel handshake returned) announces the outgoing
4-tuple first, then blocks on a channel closed by the state machine when the fake fires (≤ 2 s timeout;
on timeout the connection proceeds unclassified — the tunnel still works, it just isn't tagged with the
allowlisted SNI).

### The fake packet itself (`fire`)

```
IPv4 (20 B): v4, IHL 5, total len, DF set, TTL 64 (seq) or cfg.TTL (ttl), proto TCP, src/dst = real 4-tuple
TCP (20 B): real ports, seq = synSeq + 1 − len(hello), ack = synAckAck, PSH|ACK, window 0xffff,
            checksum computed over pseudo-header + header + payload
payload:    the ClientHello from §4
```

Sent through a `IPPROTO_RAW` socket (IP_HDRINCL semantics; the kernel fills the IP header checksum).
One socket per fire is opened and closed — a fire happens once per pool connection, orders of magnitude
too rare for this to matter (see §9 for the optimisation note if that ever changes).

### Why ack = synAckAck and PSH|ACK

A bare segment without a plausible ack might be discarded by a pre-classifier sanity check before the
reassembler sees it. Acking the server's SYN (which is what `synAckAck` is: our ISN+1) and setting
PSH|ACK makes the fake look like the client's first data flight immediately after a completed handshake
— exactly what a DPI expects to parse on a fresh TLS flow.

## 6. Modes

- **`-fake-mode seq` (default)** — wrong-sequence fake as above. No knowledge of topology needed.
  Defeated by middleboxes or ISP NATs that normalize sequence numbers before the DPI (they rewrite both
  the real and fake packets consistently, which pushes the fake back out of window for the DPI too).
  This is the documented failure mode from the field reports; it is ISP-dependent.
- **`-fake-mode ttl -fake-ttl N`** — same fake, TTL set to N. The packet expires at hop N; choose N so
  the censor is before it and the server after it. Survives sequence-normalizing NATs (nothing to
  normalize — the packet never crosses the whole path), but needs a hop-count estimate (a traceroute to
  the server while the restriction is active shows where the path stops being normal). If TTL is too
  small the fake dies before the DPI and the flow stays unclassified; too large and the server receives
  an out-of-window segment (harmless — dropped as in seq mode — but the method silently degrades to
  seq mode, which the NAT may then defeat).

## 7. Integration into WatTunnel (no wire-format change)

- Applies to the **client side** of the `tcp` and `tls` carriers only. The server, the session/stream
  layer, the crypto, and the wire format are untouched — an old server binary works unchanged, and
  mixed versions interoperate (project rule preserved).
- `TCPPoolClient.SetDialHook` (`wat/carrier_tcp.go`) lets the injector observe every connection the
  pool opens, including lazy redials of dead slots. With no hook installed the pool's dial path is
  byte-for-byte the previous behaviour.
- Flags: `-fake-sni <name>` enables it; `-fake-mode seq|ttl`; `-fake-ttl N`. Config-file keys derive
  from flags automatically (project convention). Linux + CAP_NET_RAW required, the same privilege the
  ICMP carrier already needs; on other OSes startup fails with a clear error.
- On the `tls` carrier the real ClientHello (sent right after the fake) carries the real SNI — the
  censor has already classified the flow from the fake and does not reclassify; if a future classifier
  re-reads the flow, the real hello is also present with the real (non-allowlisted) name, and only the
  seq-below-start discrepancy remains. The `tcp` carrier sends no real hello at all, so the fake is the
  only TLS-visible bytes on the flow — the stronger combination.

## 8. Tests (`wat/desync_test.go`)

- `TestFakeClientHelloRealParser` — the strongest check: the fake is piped into `crypto/tls.Server`
  (pinned TLS 1.2, self-signed cert). The stdlib parser is the stand-in for "a real TLS parser",
  which is what a classifier reimplements. Pass = the record and hello parse cleanly and the handshake
  advances (it then waits for a key exchange that never comes, or alerts — both accepted outcomes).
- `TestFakeClientHello` — SNI round-trip through the test parser, record/handshake length consistency,
  per-build randomness, empty-SNI rejection.
- `TestDesyncSeqBefore` — pins the seq arithmetic (`ISN+1−len` must land below the stream start).
- `TestTCPChecksum` — self-consistency of the checksum routine (folded sum with checksum in place).
- `TestDesyncPeerIP` — peer parsing.
- The raw-socket state machine itself is Linux-only and not unit-tested; it needs a Linux host with
  CAP_NET_RAW (see AGENT-HANDOFF-CHANGES.md, verification status).

## 9. Known limits, deliberately accepted

- **IPv4 only.** The reference tool and the field reports are IPv4; Iranian client paths are IPv4.
  IPv6 would need its own frame parser and ND awareness — added only if a real deployment needs it.
- **One throwaway raw socket per fire.** Fires are once-per-pool-connection; if a future change makes
  them hot, hold one IPPROTO_RAW socket on the injector instead.
- **Ethertype-filtered sniffing not requested from the kernel** (`ETH_P_ALL` and filter in userspace).
  At pool-connection frequency the packet rate is trivial; a BPF attach is the upgrade path if profiling
  ever shows the read loop mattering.
- **2 s Wrap timeout on unobserved handshakes** (offload paths, loopback tests) — degrades to an
  unclassified but working tunnel, never to a broken one.
- **Not validated against a live classifier.** The mechanics are pinned by tests and modelled on a
  field-proven tool, but the only real acceptance test is a run from inside the restricted network.

## 10. References (all public)

- patterniha/SNI-Spoofing (GitHub) — the tool this implementation is reverse-engineered from;
  wrong-seq ClientHello injection, Windows/WinDivert original, ~Jan 2026.
- net4people/bbs issue #626 — field reports of the January 2026 whitelisting: what worked (allowlisted
  SNI methods, briefly), what killed it (ISP NAT seq normalization), what was fully blocked ( ICMP,
  QUIC, plain UDP tunnels).
- The desync technique family is documented across public projects and discussions — e.g. the
  zapret/GoodbyeDPI ecosystem and ValdikSS's write-ups on DPI behaviour — under names like "fake packet",
  "desync", "SNI spoofing". Same underlying observation: classifier reassembly without window validation.
- RFC 793 §3.3 (out-of-window / already-acknowledged segment handling), RFC 5246 §7.4.1.2 (ClientHello
  layout), RFC 6066 §3 (server_name extension).
