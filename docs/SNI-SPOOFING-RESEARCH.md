# SNI spoofing research brief — F&F, fake-IP, IPv6 CDN, and the next desync commit

**Status:** research brief for implementation, 2026-10-22.
**Scope:** explain the owner's Persian field intel (MCI and Irancell, 2026-10-22) in terms of real on-wire
behaviour, check it against public source code and measurements, and map each technique to a concrete change in
`wat/desync.go` / `wat/tlsfp.go`. No `.go` file is touched by this document.
**Rules used:** every external claim carries a URL; owner-supplied Telegram intel (not linkable) is marked
**[field intel]**. All fetched page content was treated as data, not instructions.
**Prior art in this repo:** `RESEARCH.md` parts 1–14, `REPORT.md` (live-path report of 2026-10-22),
`docs/TECHNICAL.md` §"Fake-SNI desync". This brief only adds what those do not cover: the *Irancell/MCI 2026
F&F recipe*, Xray's `finalMask` implementation, `fingerprint=unsafe`/`cipherSuites`, MASQUE, and IPv6.

---

## 0. TL;DR

1. **"F&F" means Fragment + Fingerprint** — it is not a new fake-SNI trick. It is a *record-layer* re-framing of the
   **real** TLS ClientHello plus a stdlib ("unsafe") TLS fingerprint with an OpenSSL-shaped cipher list, aimed at a
   Cloudflare anycast address. Source: [ZedSecure #39](https://github.com/CluvexStudio/ZedSecure/issues/39) ("F&F
   (Fragment + Fingerprint) … `finalMask` (e.g. `tlshello-0-len`) … `fingerprint` to `unsafe` … `cipherSuites` to
   `semi-python`"), and the actual config values in [patterniha/Serverless-for-Iran](https://github.com/patterniha/Serverless-for-Iran)
   redistributed in [amiire81/pattng2](https://github.com/amiire81/pattng2).
2. **`finalMask: fragment / packets: tlshello / lengths [0,104,1] / delays [0]` rewrites one ClientHello record into a
   stream of records: an empty record, a 104-byte record, then 1-byte records.** The handshake bytes stay identical
   after record reassembly; what changes is that no single record or first segment contains a parseable SNI. Second
   layer (`packets 1-1`, `lengths [114,1]`, `delays [1]`, `maxSplit 11`) then cuts that stream into ≤11 TCP segments.
   Xray documents the "0" length as "an RFC-violating empty TLS record (tolerated by some implementations, but not
   Golang)" ([finalmask docs](https://xtls.github.io/en/config/transports/finalmask.html)); the implementation is
   [conn.go](https://github.com/XTLS/Xray-core/blob/main/transport/internet/finalmask/fragment/conn.go).
3. That empty handshake record is **fatal for Go TLS servers**: `crypto/tls` rejects a zero-length handshake record
   with `unexpected_message` ([Go source](https://github.com/golang/go/blob/master/src/crypto/tls/conn.go)); RFC 8446
   §5.1 forbids it ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)). So record-level F&F is only usable on a
   leg terminated by a tolerant peer (Cloudflare edge), **never** directly against Wattunnel's own Go server. Applied
   to the *injected fake* ClientHello it is safe: the server drops the fake by sequence number before TLS parsing.
4. **`fingerprint=unsafe` is a verified GFW-knocker Xray-core preset that means "do not use uTLS, use Go's
   `crypto/tls`"**: `"unsafe": nil` in the preset map
   ([tls.go](https://github.com/GFW-knocker/Xray-core/blob/main/transport/internet/tls/tls.go)) and the dialer falls
   through to `tls.Client(conn, tlsConfig)` whenever `GetFingerprint` returns nil
   ([tcp/dialer.go](https://github.com/GFW-knocker/Xray-core/blob/main/transport/internet/tcp/dialer.go)). Only on
   that path does `cipherSuites` take effect at all; uTLS presets ignore it.
5. **`cipherSuites=semi-python` is the 13-name OpenSSL/Python default preference order** (TLS 1.3 suites first, then
   ECDHE AES-GCM/ChaCha20/CBC), taken verbatim from the Serverless-for-Iran config. "Semi" is accurate: Go keeps its
   *own* TLS 1.2 suite ordering and only uses the list as a filter, so the result is Go's ClientHello skeleton with a
   Python-ish suite *set* — hence the nickname.
6. **Wattunnel cannot use this list today**: `carrier_tls.go` pins `MinVersion: tls.VersionTLS13`, and Go discards
   `Config.CipherSuites` for a TLS 1.3-only client and sends the fixed `[0x1301,0x1302,0x1303]`
   ([handshake_client.go](https://github.com/golang/go/blob/master/src/crypto/tls/handshake_client.go),
   [defaults.go](https://github.com/golang/go/blob/master/src/crypto/tls/defaults.go)). Reproducing the recipe needs
   a `-tls-min 1.2` knob plus `-tls-ciphers`, and it must run on the `-fp go` path.
7. **The MCI recipe is not a desync feature at all: it is a real dial to a Cloudflare anycast IP over IPv6**
   (`2a06:98c1:3101::6812:202f` ∈ Cloudflare `2a06:98c0::/29`, low 32 bits `0x6812202f` = `104.18.32.47` ∈
   `104.16.0.0/13`) with `fingerprint=chrome`, ECH and fragment masks cleared. Irancell's `188.114.98.0` is in
   `188.114.96.0/20` ([Cloudflare IP list](https://api.cloudflare.com/client/v4/ips)). This is an expression of a
   carrier/peer choice (wss/h2 through a Cloudflare domain), not something `wat/desync.go` can fake.
8. **Injected fake-IP packets (fake SYN to a whitelisted destination) cannot whitelist the real flow on a 5-tuple
   DPI.** They carry a different destination, hence a different flow key; they only matter against a middlebox whose
   flow key is degenerate (e.g. per source IP), which no public evidence supports. Keep `fakeip` only as an
   experiment; the genuine "IP fronting" is conclusion 7.
9. **The fake-SNI layer is IPv4-only today** (`desyncKey` is `[4]byte`, `Wrap` skips non-IPv4, `parseEthIPv4` only
   parses IPv4), so the MCI IPv6 route cannot even reach the injector. Adding IPv6 parity is a ~2 day change and is
   a prerequisite for any IPv6 field test.
10. **Highest-value next commit, in order:** (a) record-reframed *fake* hello mode in `desync.go`; (b) real-hello
    record reframing behind an opt-in for CDN legs only; (c) `-fp unsafe`/`-tls-ciphers`/`-tls-min 1.2`; (d) IPv6
    injector; (e) command/manager preset for "clean Cloudflare IP + worker domain" (no engine work). Details in §8.
11. **`patterniha/SNI-Spoofing` reference analysis & in-field remediation (2.10.11):** Source repository
    [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing). Two critical requirements were missing in
    earlier implementations: (a) *Duplicate ACK synchronization*: `fake_tcp.py` pauses the flow and waits for the
    server's RFC 793 duplicate ACK (`ACK = syn_seq + 1`) before sending the real ClientHello. Sending real data with
    zero RTT delay caused DPI flow tables to see both SNIs in the same burst and drop the flow. (b) *Clean 517-byte Chrome
    template*: `ClientHelloMaker` builds a 517-byte template with RFC 7685 padding (`0x0015`) and NO ECH GREASE (`0xfe0d`),
    which Iranian DPI middleboxes actively filter. (c) *Auto small ClientHello*: `-fake-sni` now implies `tls-small-ch`,
    preventing 1.5 KB post-quantum ClientHello drops.

---

## 1. Ground truth: what the current code does

### 1.1 Fake-SNI injector

`wat/desync.go` builds, on the client, one raw IPv4+TCP packet per pool connection carrying a
`FakeClientHello(sni)` (`wat/desync.go:100`, ~354 B with the built-in ECH GREASE extension at
`wat/desync.go:131-149`). (Line numbers in this section are from the revision *before* the parallel task-2 round,
which rewrote parts of `desync.go`; the symbol names are stable.) Modes (`DesyncConfig`, `wat/desync.go:55-60`;
validation `:75-94`):

| Mode | Wire trick | Server sees |
|---|---|---|
| `seq` | seq = stream start − len(hello), valid checksum | old duplicate, drops it |
| `ttl` | any seq, TTL = peer TTL − 1 (auto-calibrated from SYN-ACK) | never sees it |
| `sum` | in-window mirror of the first data segment, **damaged TCP checksum** | drops at checksum |
| `seqsum` | both markers ~1 ms apart | drops both |
| `rst` | in-window RST\|ACK with damaged checksum | drops before flags |

The packet builder is `fakePacketWithOptions` (`:269`), the RST builder `fakeRSTPacket` (`:311`), the checksum
damage `damageChecksum` (`:680`). TCP options of the kernel's own outbound segments (e.g. timestamps) are mirrored
into the fake (`c.tcpOpts`, `:569-572`) so option-consistency DPIs do not flag it. The injector is one AF_PACKET
sniffer plus a raw `IPPROTO_RAW` send per fire (`wat/desync_linux.go:199-231`); firing is anchored to the handshake's
final ACK when `TCP_REPAIR` works, else to the first outbound data segment (`wat/desync.go:577-598`).
**At the start of this research pass the engine emitted one fake packet per connection; the parallel task-2 round in
the working tree adds `split`, `hlen0`, `fakeip`, `synrst` and `all`. §6.1 grades that round against the wire
behaviour derived below; the two genuinely missing pieces are the true F&F record plan and the real-hello variant.**

### 1.2 TLS engine

`wat/tlsfp.go` owns real-ClientHello shaping for `tls`/`wss`/`h2`/`grpc`:

- `Fingerprint`: `go|chrome|firefox|safari|edge|random` (`:35`, `NormFingerprint`). `go` = Go stdlib; the others go
  through uTLS with a modified ALPN (`:327-371`).
- `Frag`: splits the **first TLS write** into N-byte TCP segments, 1 ms apart (`writeFragments` `:82`,
  `fragConn` `:101-124`). It does **not** touch TLS record headers — this matters in §3.6.
- `NoPQ`: drops the post-quantum hybrid key share so Go's ClientHello stays ~250 B instead of ~1474 B
  (`carrier_tls.go:38-51`), the fix that made the live handshake pass on 2026-10-22.
- `config()` hard-codes `MinVersion: tls.VersionTLS13` (`carrier_tls.go:39`).

### 1.3 What the live path actually measured (REPORT.md)

The 2026-10-22 path (Iran 192.0.2.10 → Kharej 198.51.100.20, AS51396) is **not** an MCI/Irancell mobile path:
a flow-aware filter that drops unknown *payload* after a classification timeout, caps HTTP GET bodies at 14,480 B
per connection, blocks POST bodies outright, and lets 1474 B hellos vanish while 250–512 B hellos pass
(`REPORT.md` §3, §7–7c). Consequences for this brief:

- A handshake-only trick can make the tunnel *connect*; it cannot by itself beat a payload/volume filter. Keep
  `pool-rotate` and the CDN route on the table.
- `-tls-frag` (TCP segmentation only) was already tested indirectly: the filter reassembles, so TCP-level splitting
  is not the F&F mechanism and will not fix this path ([bbs #628](https://github.com/net4people/bbs/issues/628)
  reports full TCP reassembly in Iran; [bbs #640](https://github.com/net4people/bbs/issues/640) says fragmented
  tlshello stopped passing).
- The MCI/Irancell recipes in §2 are **mobile-ISP** recipes from a different vantage point; treat them as
  hypotheses for the next field test, not as facts about the 198.51.100.20 path.

### 1.4 Gaps this brief targets

1. The fake hello is one un-fragmented, un-re-framed record; the F&F class of DPIs is never exercised by it.
2. The real hello can only be split at the TCP layer (`tls-frag`), not at the TLS-record layer (`tlshello`).
3. No "unsafe"/Go-stdlib + cipher-list + min-version control on the TLS engine.
4. No IPv6 anywhere in the fake-SNI path.
5. No classification of *why* a route works, so field intel cannot be turned into a testable config.

---

## 2. The owner's field intel, decoded

**[field intel]** = Persian Telegram channel, supplied by the owner on 2026-10-22; not linkable, unverified except
where cross-checked below. MCI = هم‌راه اول (AS197207), Irancell = ایرانسل (AS44244).

| # | Intel (verbatim gist) | What it means technically | Grounding |
|---|---|---|---|
| MCI-1 | CDN/Worker with **IPv6** + an unfiltered personal domain (or `workers.dev.*`; `pages.dev.*` fully blocked): clear `echConfigList`/`cipherSuites`/`finalMask`, `fingerprint=chrome`, connect to an IPv6 address such as `2a06:98c1:3101::6812:202f` | A **real** TLS/WS dial to a Cloudflare anycast address over IPv6, standard Chrome-uTLS hello, no ECH, no masks. The IPv6 edge is chosen because MCI's IPv6 path is less filtered ("IPv6 is measurably less filtered on mobile" was also seen in `RESEARCH.md` §1.2). | `2a06:98c1:` is Cloudflare (`2a06:98c0::/29`); Cloudflare's IPv6 anycast embeds the IPv4 in the low 32 bits: `0x6812202f` = 104.18.32.47, inside Cloudflare `104.16.0.0/13` ([Cloudflare IPs](https://api.cloudflare.com/client/v4/ips)) |
| MCI-2 | WARP over IPv6 (WireGuard) | Route-level fallback: a real WireGuard tunnel to a Cloudflare WARP endpoint over IPv6 | Cloudflare WARP docs ([Linux client](https://developers.cloudflare.com/warp-client/get-started/linux/)) |
| MCI-3 | MASQUE-HTTP/2 | Route-level fallback: a real MASQUE proxy tunnel over HTTP/2 (Cloudflare Privacy Proxy/WARP accept HTTP/2 and HTTP/3) | Cloudflare Privacy Proxy supports HTTP/2 and HTTP/3 with `CONNECT`/`CONNECT-UDP` ([docs](https://developers.cloudflare.com/privacy-proxy/concepts/how-it-works/)) |
| Irancell-1 | CDN/Worker with the **F&F method**: clear `echConfigList`, use `188.114.98.0` (a Cloudflare edge), `finalMask=tlshello-0-len`, `cipherSuites=semi-python`, `fingerprint=unsafe`, ALPN `http/1.1` for ws (`h2,http/1.1` for XHTTP). **Other methods are upload-throttled on Irancell.** | Record-reframed real ClientHello + Go-stdlib fingerprint + OpenSSL-shaped suite list, dialing a Cloudflare edge IPv4, ALPN matching the transport. | Values verified against the real config in §3.3; `188.114.98.0` ∈ `188.114.96.0/20` ([Cloudflare IPs](https://api.cloudflare.com/client/v4/ips)) |
| Irancell-2 | WARP any IP | Same as MCI-2 | — |
| Irancell-3 | MASQUE/H2 | Same as MCI-3 | — |
| Both | `cloudflare-ech.com` is now blocked entirely, so ECH-based routes are dead | ECH's fronting/bootstrap domain is filtered; ECH cannot be used on these ISPs; Wattunnel's `-ech` ladder must treat "config fetch fails" as "ECH off" and not stall. | ECH is [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html); `cloudflare-ech.com` is Cloudflare's public-name fronting domain in its ECH deployment (Cloudflare ECH configs name it). Blocking of the ECH front domain has been reported for other censors; here it is **[field intel]** |

The important structural reading: **MCI and Irancell solved the same problem in two different layers.** MCI uses the
routing layer (connect to a different, unfiltered *IP family* and address) and leaves the TLS stack alone. Irancell
uses the parsing layer (keep the same Cloudflare IPv4 but break the DPI's record/segment view of the hello) because
on Irancell the route/tunnel class is recognised and upload-throttled. That matches the general Iranian pattern:
enforcement is per-ISP/ASN and per-segment, not global (`RESEARCH.md` §1.7; [RandLab allowlist study](https://randlab.engineering.ucsc.edu/blogs/iran-allowlist/)).

---

## 3. F&F = Fragment + Fingerprint

### 3.1 What the name means

[ZedSecure issue #39](https://github.com/CluvexStudio/ZedSecure/issues/39) (a feature request describing
"PattNG-style" presets) gives the expansion and the exact knobs:

> **F&F (Fragment + Fingerprint):** Auto-injecting `finalMask` (e.g. `tlshello-0-len` or the full JSON fragment
> packets), setting `fingerprint` to `unsafe`, and `cipherSuites` to `semi-python`.
> **Clean IP Replacement:** … a clean Cloudflare IPv4 (e.g. `188.114.97.6`) or IPv6 (e.g. `2a06:98c1:3121::7`) …
> **ECH Profiles:** … resetting conflicting fragment/cipher fields.
> **ALPN Normalization:** `http/1.1` for WS or `h2,http/1.1` for XHTTP.

The same values are shipped in [patterniha/Serverless-for-Iran](https://github.com/patterniha/Serverless-for-Iran)
(redistributed with the F&F values in [amiire81/pattng2](https://github.com/amiire81/pattng2) and summarised in
[amiire81/pattng3](https://github.com/amiire81/pattng3)), and extracted as a named preset
`profiles/pattng-tlshello-0-len.json` in
[xray-fragment-scanner](https://github.com/malekjani/xray-fragment-scanner/blob/main/profiles/pattng-tlshello-0-len.json).

### 3.2 Xray `finalMask` fragment semantics (the code that produces the wire)

Docs: [`finalMask`](https://xtls.github.io/en/config/transports/finalmask.html) — `packets: "tlshello"` fragments
the TLS handshake packet; `lengths` is a per-fragment byte plan where "the last element keeps applying to all
subsequent fragments"; entries other than the last may be `0` — "for tlshello, it behaves as sending an RFC-violating
empty TLS record (tolerated by some implementations, but not Golang)"; `delays` are inter-fragment sleeps, and with
a single `0` "the fragmented Client Hello will be sent in a single TCP packet"; `maxSplit` limits the pieces.

The implementation
([`transport/internet/finalmask/fragment/conn.go`](https://github.com/XTLS/Xray-core/blob/main/transport/internet/finalmask/fragment/conn.go))
acts on the **first write**, i.e. the real TLS ClientHello record `p`:

```go
// simplified from the upstream conn.go
recordLen := 5 + int(p[3])<<8 | int(p[4])     // TLS record header
data := p[5:recordLen]                        // handshake bytes, length |H|
merge := len(delays) == 1 && delays[0] == 0   // single 0-delay => write once
for from := 0; ; {
    l := rand(lengths[segment])               // 0, 104, then 1 forever for the PattNG preset
    to := min(from+l, len(data))
    out := append([]byte{p[0], p[1], p[2], byte(to-from >> 8), byte(to - from)}, data[from:to]...)
    from = to
    if merge { buffered = append(buffered, out...) } else { conn.Write(out); sleep(delay) }
    if from == len(data) { if merge { conn.Write(buffered) }; return }
}
```

Two properties that matter:

1. **Every fragment gets a fresh, correct-looking TLS record header** (`16 03 01 <len>`), and the payload stays the
   original handshake byte stream. A TLS peer that concatenates record payloads reassembles the ClientHello
   *unchanged*; a lenient peer (Cloudflare edge in the field recipe, per **[field intel]**) tolerates the empty
   record and completes the handshake, while Go's `crypto/tls` does not (§3.6).
2. With `lengths: ["0","104","1"]` the payload is chopped as `H[0:0]`, `H[0:104]`, `H[104:105]`, `H[105:106]`, …
   so **no record after the first contains more than one byte of the handshake**, and the first non-empty record
   stops at byte 104.

### 3.3 The exact Irancell F&F preset (byte plan)

The preset, identical in the Serverless config and the scanner profile:

```json
"finalMask": { "tcp": [
  { "type": "fragment", "settings": {
      "packets": "tlshello", "lengths": ["0","104","1"], "delays": ["0"], "maxSplit": "0" } },
  { "type": "fragment", "settings": {
      "packets": "1-1", "lengths": ["114","1"], "delays": ["1"], "maxSplit": "11" } }
]}
```

with `"fingerprint": "unsafe"`, `"cipherSuites": "<13-name list>"`, ALPN `http/1.1` (WS) or `h2,http/1.1` (XHTTP),
`security: tls` to a Cloudflare edge (`188.114.98.0`, `188.114.97.6`, …), `serverName` = the Cloudflare-proxied
domain **with mixed letter case** (e.g. `ZeCqRti6Sp0-IzkSWM9spG9g.DaSHaXx1.wOrKerS.DEv`), reflecting the use of the
same case-randomisation trick that `zapret --domcase` applies to HTTP Host headers
([zapret docs](https://github.com/bol-van/zapret/blob/master/docs/readme.en.md)).

Resulting stream for a real hello whose record payload is `H` (`|H| = recordLen − 5`, usually 245–1500 bytes):

```
mask 1 output R (one write, "delays":["0"]):
  [16 03 01 00 00]                       empty record          (5 B)
  [16 03 01 00 68] H[0:104]              first 104 handshake B (109 B)
  [16 03 01 00 01] H[104]                record per byte       (6 B each)
  [16 03 01 00 01] H[105]
  …
  [16 03 01 00 01] H[|H|-1]
  ⇒ |R| = 114 + 6·(|H| − 104)            for |H| ≥ 104
     e.g. Go small CH |H|≈245 → |R|≈960 B; Go default CH |H|≈1469 → |R|≈8.3 KB

mask 2 cuts R into TCP segments ("packets":"1-1", lengths ["114","1"], delays ["1"], maxSplit 11):
  R[0:114] → R[114:115] → … → R[122:123] (nine 1-byte pieces) → R[123:] as the final segment
  ⇒ 11 TCP pieces total (maxSplit 11), with a 1 ms sleep after each of the first 10
```

What a middlebox sees depends on where it looks:

| Middlebox implementation | What it extracts | Outcome |
|---|---|---|
| Parses **only the first TLS record** of the flow | an *empty handshake record* → no SNI | fail-open (allow) or unclassified; the SNI never appears |
| Parses **only the first TCP segment** | empty record + a 104 B record whose payload ends inside the `server_name` host name (the extension starts at ~89 for a 32-byte session id; the host name at ~98), then 2 one-byte records | no complete SNI in the segment |
| Reassembles TCP, then concatenates **all record payloads** | the unmodified ClientHello | sees the SNI; this implementation is **not** defeated (matches [bbs #628](https://github.com/net4people/bbs/issues/628)) |
| Has a "handshake must be parseable in the first N bytes/segments, else block" rule | truncated/empty-record stream | block (this is why the recipe is ISP-specific) |
| Fingerprints `unsafe`+cipher-list/JA4 | Go extension order, no GREASE, Python-like 1.2 suite *set* | classifies as a non-browser Go/Python client; on Irancell that is within the allowed class (**[field intel]**, effect not independently measurable) |

The honest ranking of *why* Irancell's specific DPI is fooled: (1) first-record/first-segment triage that fails
open on an empty or SNI-less record; (2) a record parser that trips on a zero-length handshake record and skips the
flow; (3) per-segment size/shape heuristics (the real hello never appears as one big segment, which again matters on
paths where large hellos are dropped — see `REPORT.md` §7c). Which of the three it is can only be settled by the
local emulator (§9), not by reading the config.

### 3.4 What it costs

- Extra bytes: ~5.6× the handshake record for a default Go hello, ~3.9× for the small one; ~2–8 KB per connection.
- Extra segments: 11 (mask 2: 114 B, nine 1-byte pieces, remainder) with a 1 ms delay after the first 10 pieces;
  the BPB docs recommend 1–20 ms fragment delays and warn that the handshake is one-shot
  ([BPB fragment docs](https://github.com/bia-pain-bache/BPB-Worker-Panel/blob/main/docs/en/docs/configuration/fragment.md)).
- Zero cost after the handshake: the masks only act on the first TLS write (`packets tlshello`, and `1-1`).

### 3.5 Raw-packet translation for `wat/desync.go` (fake-hello variant)

The fake hello never reaches the server, so it may contain RFC-violating records; the only reader is the DPI. New
pure builder + segmented fire, reusing today's anchors (`base = c.synSeq+1` or first-data-segment seq, `ack` as
today) and `fakePacketWithOptions`:

```go
// wat/desync.go (new, pure)
// recordReframe rewrites hello (a 5-byte record + handshake) into the F&F record plan.
// first=0 inserts an empty record; chunk=104; tail=1 byte per record. No delays here.
func recordReframe(hello []byte, first, chunk, tail int) []byte

// fakeSegs cuts b into the TCP plan (lengths, maxSplit) and returns the pieces.
func fakeSegs(b []byte, lengths []int, maxSplit int) [][]byte

// fireSegmentedLocked sends the pieces as separate raw packets below the stream start.
func (t *desyncTracker) fireSegmentedLocked(k desyncKey, c *desyncConn, base, ack uint32, hello []byte) {
    r := recordReframe(hello, 0, 104, 1)
    off := 0
    for _, seg := range fakeSegs(r, []int{114, 1}, 11) {
        seq := base - uint32(len(r)) + uint32(off)     // every segment < base: server drops as old duplicate
        t.send(fakePacketWithOptions(k, seq, ack, 64, seg, c.tcpOpts))
        off += len(seg)
        // 1 ms spacing (the preset's "delays") MUST NOT sleep under t.mu: either send from a goroutine
        // after unlocking, or collect the packets and space them in the caller (the seqsum path does
        // exactly this with time.AfterFunc for its second marker).
    }
    if ch := t.wait[k]; ch != nil { /* same close dance as fireLocked today */ }
}
```

Wire sequence, concretely (base = `ISN+1` = e.g. `0x11223344`; `|R|` = 960 for a small fake hello):

| # | seq | flags | payload |
|---|---|---|---|
| 1 | `base−960` | PSH\|ACK, ack = server SYN-ACK seq | `R[0:114]` |
| 2 | `base−846` | PSH\|ACK | `R[114:115]` |
| … | | | 9 one-byte pieces, offsets 114…122 |
| 10 | `base−838` | PSH\|ACK | `R[122:123]` |
| 11 | `base−837` | PSH\|ACK | `R[123:]` (remainder) |

All checksums valid, TTL 64 by default (or `-fake-mode ttl` semantics if calibrated), no IPv4 options, DF set, same
4-tuple as the real flow. A censor that validates windows ignores every piece (same weakness as `seq`); the
`sum`/`seqsum` variants can be combined later by sending in-window copies with `damageChecksum`.

### 3.6 The **real-hello** variant (what actually reproduces F&F)

The field recipe reframes the *real* ClientHello, which in Wattunnel is written by `crypto/tls`/uTLS during
`handshake1` (`wat/tlsfp.go:292-322`). The equivalent of Xray's `fragmentConn` is a wrapper on the raw TCP conn
installed where `newFragConn` is installed today (`wat/tlsfp.go:293`):

```go
// wat/tlsfp.go (new): rewrites the first TLS write into the F&F record plan, then writes it as ≤N segments.
func newRecordFragConn(c net.Conn, first, chunk, tail int, lengths []int, maxSplit int) net.Conn
```

But: **the empty handshake record breaks every Go TLS server.** Go's `crypto/tls` treats a zero-length
`recordTypeHandshake` as `unexpected_message` ([conn.go](https://github.com/golang/go/blob/master/src/crypto/tls/conn.go)),
and RFC 8446 §5.1 says implementations "MUST NOT send zero-length fragments of Handshake types"
([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)). The upstream Xray doc says the same ("not Golang").
Therefore:

- On a **direct** `tls`/`wss`/`h2`/`grpc` pool connection to Wattunnel's own server: the record-reframed real hello
  must not be used; the handshake will fail.
- On a **Cloudflare-terminated** leg (client → CF, CF → origin is a separate connection), the empty record is
  tolerated in practice ([field intel] is the only evidence; Xray's docs describe the same tool being used against
  CDNs). This is the only leg where the recipe belongs.
- The safe, immediately shippable half is therefore the **fake** hello (§3.5): the server discards it by sequence and
  never parses it, while the DPI sees the exact F&F record stream.

---

## 4. `cipherSuites=semi-python` and `fingerprint=unsafe`

### 4.1 `fingerprint=unsafe` = "no uTLS, Go `crypto/tls` hello"

Verified in the GFW-knocker Xray-core core used by MahsaNG/PattNG-class clients:

- `PresetFingerprints` contains `"unsafe": nil`
  ([tls.go](https://github.com/GFW-knocker/Xray-core/blob/main/transport/internet/tls/tls.go)).
- `GetFingerprint("unsafe")` therefore returns `nil`, and the TCP transport falls to the stdlib branch:
  `conn = tls.Client(conn, tlsConfig)`
  ([tcp/dialer.go](https://github.com/GFW-knocker/Xray-core/blob/main/transport/internet/tcp/dialer.go)).
- `infra/conf/transport_security.go` allows `unsafe` for plain TLS (it is rejected only for REALITY, which needs a
  uTLS-shaped hello). The ECH code comments call the two paths "uTLS path and crypto/tls path"
  ([ech_selfhosted_test.go](https://github.com/GFW-knocker/Xray-core/blob/main/transport/internet/tls/ech_selfhosted_test.go)).

Wattunnel's `-fp go` is the same thing (`useUTLS()` returns false for `go`, `wat/tlsfp.go:194`). So "fingerprint=unsafe"
in the recipe is reproducible today as `-fp go` — with the caveat in §4.3.

### 4.2 The cipher list is OpenSSL/Python's default set

The 13 names in the Serverless config (verified all occurrences, e.g. line 92 of the pattng2 JSON):

```
TLS_AES_256_GCM_SHA384 : TLS_CHACHA20_POLY1305_SHA256 : TLS_AES_128_GCM_SHA256 :
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 : TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 :
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 : TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 :
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 : TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 :
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA : TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA :
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 : TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
```

This is OpenSSL's default preference order truncated to ECDHE suites — i.e. what a Python `ssl` client offers
(Python uses OpenSSL's defaults). The nickname "semi-python" is accurate in the same sense as §4.1: it is a Python
*suite set* on a Go hello, not a Python hello.

There is also a separate PattNG profile for a Firefox-like list
([`pattng-real-firefox-cipherSuites.txt`](https://github.com/malekjani/xray-fragment-scanner/blob/main/profiles/pattng-real-firefox-cipherSuites.txt)),
so the community treats these lists as named personas; do not hardcode one list as "the" F&F list.

### 4.3 What Go actually does with the list (and why Wattunnel is currently immune)

Verified in the local Go 1.26 toolchain:

1. Xray parses `cipherSuites` by name against `tls.CipherSuites()` / `tls.InsecureCipherSuites()` and appends the
   IDs in the user's order (`transport/internet/tls/config.go`, "if len(c.CipherSuites) > 0").
2. Go **does not honour that order**: `Config.cipherSuites()` starts from Go's own `supportedCipherSuites()` order and
   only *deletes* IDs that are not in the configured list
   ([common.go](https://github.com/golang/go/blob/master/src/crypto/tls/common.go)). So the list is a set filter, not
   an order.
3. If `MinVersion >= TLS 1.3`, Go **discards the 1.2 list entirely** and sends the fixed TLS 1.3 suites
   (`hello.cipherSuites = nil; append(defaultCipherSuitesTLS13…)`,
   [handshake_client.go](https://github.com/golang/go/blob/master/src/crypto/tls/handshake_client.go);
   `defaultCipherSuitesTLS13 = [0x1301,0x1302,0x1303]`,
   [defaults.go](https://github.com/golang/go/blob/master/src/crypto/tls/defaults.go)).
4. With `MinVersion = TLS 1.2` (Xray's default when `minVersion` is unset) the hello carries the filtered 1.2 set in
   Go's order **followed by** the three TLS 1.3 suites appended at the end — which is why the Xray configs can have a
   visible cipher-list effect at all.
5. Go never sends GREASE ([RFC 8701](https://www.rfc-editor.org/rfc/rfc8701.html)) and its extension order is Go's
   own. uTLS `chrome`/`randomized` presets do send GREASE; `HelloCustom` can be told to.

Wattunnel's `config()` sets `MinVersion: TLS13` (`wat/carrier_tls.go:39`), so **at present the `semi-python` list
would be a no-op even if a flag existed**. Exact reproduction in Wattunnel requires `-tls-min 1.2`
(which then still negotiates 1.3 in practice but shows the 1.2 set to the DPI) plus `-tls-ciphers <13 names>`, on the
`-fp go` path. That hello is ~250–300 B with `-tls-small-ch`, matches the field recipe's *visible* properties
(Go skeleton, Python-like suite set, no GREASE, no ECH), and is the honest ceiling of what can be reproduced
byte-for-byte without forking Go's TLS stack.

### 4.4 The "3-byte cipher" claim

There is no 3-byte cipher suite encoding in TLS: cipher suite IDs are 2 bytes in both TLS 1.2 and 1.3
([RFC 8446 §4.2.1 / Appendix B](https://www.rfc-editor.org/rfc/rfc8446.html)). The only 3-byte field near the top of
a ClientHello is the handshake message length. When the community says "3-byte cipher" it is describing one of two
things: (a) a DPI parser desynchronised by the 3-byte handshake length vs. the 2-byte record length (exactly the
mismatch F&F's empty record creates), or (b) bogus uTLS `HelloCustom` cipher values used as a parser canary. Do not
implement anything called "3-byte cipher" — implement the record/length mismatch (`fragrec`) or GREASE, whichever the
emulator shows the target DPI mishandles.

The "CVE-adjacent" part of the method is exactly this class of **parser differential**, not a memory-safety exploit:
a record sequence that is invalid per RFC 8446 §5.1 but tolerated by one TLS stack and rejected by another makes
different boxes reach different verdicts about the same flow. That is also why the F&F recipe must be aimed at a
specific TLS terminator (Cloudflare edge, §3.6) — a parser differential only helps if the *server* is on the tolerant
side of it.

### 4.5 ECH and `cloudflare-ech.com`

ECH itself is [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html). Cloudflare's ECH deployment names a public
front domain (`cloudflare-ech.com`) in the HTTPS records it serves; if that name is filtered, a client cannot
fetch an ECH config and the outer ClientHello cannot hide its SNI. Wattunnel's `-ech auto|ladder` gets its config
from DoH/HTTPS (or through the tunnel for `ladder`), so it can technically survive DNS filtering — but on these ISPs
**[field intel]** says all ECH routes are dead. Keep ECH code, but do not spend next-commit effort on it; the
MCI/Irancell recipes explicitly clear `echConfigList`.

---

## 5. Fake-IP, IPv6 CDN, and which DPI key to spoof

### 5.1 The only "fake IP" with field evidence: dial a *real* whitelisted CDN IP

The successful recipes do not spoof IPs; they choose the destination. `188.114.98.0` (Irancell) and
`2a06:98c1:3101::6812:202f` (MCI) are both real Cloudflare anycast addresses
([Cloudflare IPs](https://api.cloudflare.com/client/v4/ips): `188.114.96.0/20` and `2a06:98c0::/29`), and the SNI/Host
is a domain that Cloudflare actually serves (personal zone proxied by Cloudflare, or a `workers.dev` worker). This is
**SNI↔IP consistency by construction**: the SNI names a zone whose authoritative/IP owner is the destination the
client actually dials. That is what defeats an SNI-vs-destination cross-check (if Iran runs one — `RESEARCH.md`
Part 13 hypothesised it; it has never been demonstrated in public measurement).

Wattunnel already supports the shape of this without any engine work: `peer` may be an IP:port while `sni` and
`host` are the Cloudflare-fronted name (`carrier: wss`, `-peer 188.114.98.0:443 -sni <worker>.workers.dev
-host <worker>.workers.dev`). `REPORT.md` §7b proved Cloudflare reaches the origin and returns `101 Switching
Protocols` even from this heavily filtered path — the remaining failure is on the *data* leg, not the handshake.
The IPv6 variant needs a client host with working IPv6; the Iran VPS used in `REPORT.md` has **none** (link-local
only, §7 round 2), so the MCI-1 recipe is untestable from that host.

### 5.2 Why an injected fake SYN to a whitelisted IP cannot whitelist the real flow

The proposed `fakeip` mode sends a raw packet from the client's IP/port to a whitelisted destination (e.g. a
Cloudflare edge) with a bogus sequence, so a "DPI that keys flows by destination IP" records the flow as allowed.
That only works if the DPI's flow key collides with the real flow's key. What is known about the keys:

| Key candidate | Evidence | Does a fake SYN to another IP collide? |
|---|---|---|
| 5-tuple (src IP, src port, dst IP, dst port) | Every stateful middlebox (zapret's own conntrack model); a 4-tuple is the minimum for NAT/state | **No** — different `dst IP` = different flow |
| (client IP, server IP) pair | Not reported anywhere | No — still different server IP |
| Per-client-IP allowlist state | [RandLab](https://randlab.engineering.ucsc.edu/blogs/iran-allowlist/) shows the allowlist is source-IP based | Maybe, but the allowlist is for *which Iranian IPs may egress at all*, not per-flow classification; a fake SYN does not change the client's IP |
| Per-(client IP, client port) | Speculative | Maybe, if the DPI reuses the same slot; a different server port still differs |
| SNI allowlist layered on top | [RandLab](https://randlab.engineering.ucsc.edu/blogs/iran-allowlist/): "SNI filtering … still exists as a blocklist layered on top of IP-based allowlisting … only for roughly half of allowlisted IPs"; random never-registered SNIs pass | **No** — this key is the SNI in the real flow's hello |

Conclusion: `fakeip` as a *whitelisting* mode is not supported by any flow-key evidence and should be treated as a
cheap experiment (`fakesyn`), not as a fix. What a middlebox-state trick *can* do — and what `rst`/`seqsum` already
exploit — is clear or confuse the DPI's per-flow state with a packet that is dropped by the server's kernel. A fake
SYN/SYN-ACK with a damaged checksum or wrong sequence is a variant of that class (zapret's `synack` 0-phase mode:
[readme](https://github.com/bol-van/zapret/blob/master/docs/readme.en.md)); it targets boxes that treat the first
SYN/SYN-ACK as the classification point, not boxes that whitelist by destination IP.

### 5.3 Which key to spoof — practical ranking

1. **The real flow's SNI/record shape** (F&F, Fragment+Split, ECH): the only key every published Iranian measurement
   agrees is read. No IP spoofing needed.
2. **The real destination IP** by *actually* dialing a whitelisted CDN anycast address and carrying traffic through
   it (Cloudflare front). Then SNI and IP agree; no consistency check can fire.
3. **Middlebox flow state** (`rst`-class, maybe `synrst`): cheap, no IP spoofing, works only on stateful boxes whose
   policy is "stop inspecting once classified".
4. **A synthetic other-IP flow** (`fakeip`): no collision with the real key; keep as an experiment at most.

### 5.4 IPv6 in Wattunnel today

The fake-SNI layer is IPv4-only end to end:

- `desyncKey` is `{srcIP, dstIP [4]byte; srcPt, dstPt uint16}` (`wat/desync.go:257-263`).
- `fakePacketWithOptions`/`fakeRSTPacket` write an IPv4 header (`pkt[0]=0x45`, `:269-331`).
- `parseEthIPv4` knows Ethernet/SLL/raw-IPv4/VLAN but not IPv6 (`:333-355`).
- `handleIPv4` rejects non-IPv4 (`:508-511`).
- `NewDesync` rejects a non-IPv4 `peer` (`desync_linux.go:79-80`), and `Wrap` passes through any connection whose
  socket addresses are not IPv4 (`desync_linux.go:104-108`).

So on an IPv6 path the module silently does nothing (the tunnel still works, just unclassified). Making the MCI-1
recipe usable needs IPv6: `parseEthIPv6` (no IPv4-style header length; next-header walk over extension headers),
`desyncKey6` ([16]byte addresses), `fakePacket6` (IPv6 header + TCP checksum over the IPv6 pseudo-header, hop limit
instead of TTL, no IP checksum), `NewDesync` accepting an IPv6 peer, and `sendRawPacket6` (`AF_INET6`, `IPPROTO_RAW`,
`IPV6_HDRINCL`). ~250 lines with tests; see §8 item 4.

---

## 6. Primitive catalogue (implementation map)

Sizes are order-of-magnitude for the current codebase. "Wire" = what changes relative to today. Target = which
filter class this is for. Throughput = expected effect on the *data* phase (all these are first-flight/
classification tricks; none creates bandwidth).

| # | Primitive | Wire change | Target | Throughput | Implementation sketch (`wat/…`) | Risk | Size |
|---|---|---|---|---|---|---|---|
| P1 | **`fragrec`** — fake hello record-reframed (true F&F `tlshello-0-len` shape) | fake ClientHello becomes `empty record + 104 B record + 1 B records`, sent as ≤11 TCP segments below the stream start (seq arithmetic as `seq`, valid checksums) | Irancell/MCI-class record/segment-triage DPI | none directly; lifts upload throttling only if throttling is classification-based | `recordReframe(hello, 0, 104, 1)`, `fakeSegs(r, []int{114,1}, 11)`, loop in a new `fireSegmentedLocked` using `fakePacketWithOptions`; new `DesyncConfig.Mode == "fragrec"`; 1 ms gaps via `time.AfterFunc` or a goroutine (never sleep under `t.mu`) | low: fake never reaches server; only DPI sees it. Must not be picked by `auto` until field-tested | ~100 LOC + tests |
| P2 | **`hlensplit`** — fake hello as N plain TCP segments (no record rewrite), cut inside the SNI host_name | same fake bytes, seq below the stream start, pieces of 114/1 B | DPIs that parse only the first segment and fail open | none | `fakeSegs(hello, plan, maxSplit)` only (no `recordReframe`); `-fake-split K,L` config | low | ~40 LOC |
| P3 | **real-hello `fragrec`** (`-tls-frag-rec`) | the real ClientHello's first write is re-framed into the F&F record plan before it leaves | Irancell via Cloudflare; any DPI that triages the first record/segment | +10 ms handshake; the only primitive that reproduces the field recipe literally | `newRecordFragConn` wrapper in `wat/tlsfp.go` around the first `Write` (replaces/extends `newFragConn`); config `-tls-frag-rec 0,104,1 / 114,1 / 11`; only enable for CDN legs | **high**: zero-length handshake record is rejected by Go TLS servers (RFC 8446 §5.1; Go `conn.go`), so it must never be on for a direct Wattunnel peer; also a middlebox that reassembles records loses the trick entirely | ~80 LOC + tests |
| P4 | **`-tls-min 1.2` + `-tls-ciphers <list>`** on `-fp go` | Go ClientHello offers a TLS-1.2-filtered suite set + the 1.3 defaults; Python/OpenSSL-shaped suite set | Irancell F&F fingerprint half | none | `TLSClientOptions.MinVersion/CipherSuites`; `config()` sets `MinVersion`, `CipherSuites` by name → `tls.CipherSuites()` lookup (mirror Xray's parser); validate names; `-fp unsafe` alias for `go` | low, but list only filters Go's set (§4.3) — do not claim byte-equality with Python | ~60 LOC + tests |
| P5 | **IPv6 fake-SNI** | IPv6+TCP fake packets; v6 flow key; v6 sniffer | MCI IPv6 route; any AAAA-only path | none | `parseEthIPv6`, `desyncKey6`, `fakePacket6`, `fakeRSTPacket6`, `sendRawPacket6`, `NewDesync` v6 peer, `Wrap` v6 keys | low wire risk; needs CAP_NET_RAW on a v6-capable host; +1 MTU consideration (no IPv4 DF) | ~250 LOC + tests |
| P6 | `synrst` (landed as `synrst`) — fake SYN\|RST with damaged checksum, in-window | one extra packet per flow, kernel drops it at checksum | middleboxes that classify on 0-phase handshake / clear tables on RST | none | landed: `fakeFlagPacket(k, base, ack, ttl, 0x06)` + `damageChecksum` | medium: an in-window RST/SYN that survives a reroute can tear the real connection (same caveat as `rst`); SYN\|RST is an IPS anomaly signal | 0 (landed) |
| P7 | `fakeip` (landed as `fakeip`) — fake SYN + hello from client IP/port to a whitelisted destination IP | new 4-tuple; server never sees it (different dst), kernel sends it to the CDN | only a degenerate DPI whose flow key collides | no expected effect (see §5.2) | landed: `fakeFlagPacket` SYN + `fakePacketWithOptions` hello to `cfg.FakeIP` (default 104.16.0.1:443) | low wire risk, high field-anomaly risk (unsolicited SYN to a CDN IP from a machine that already talks to a foreign host), no expected benefit | 0 (landed) |
| P8 | TTL fake (exists) | TTL = peer hop − 1 | any path where TTL is not normalised | none | already there; extend to IPv6 hop limit with P5 | existing | 0 |
| P9 | badsum fake (exists) | in-window mirror, damaged TCP checksum | filters that validate sequence but not checksum | none | already there (`sum`/`seqsum`); add IPv6 variant with P5 | existing (checksum-validating NATs) | 0 |
| P10 | bad-checksum RST (exists) | RST\|ACK, damaged checksum | stateful filters | none | already there (`rst`); P6 is its 0-phase cousin | existing | 0 |
| P11 | multi-marker `all` (landed) | sequence of `seq` + `sum` + `hlen0` markers 1 ms apart | filters that need more than one signal | none | landed: `time.AfterFunc` spacing as in the `seqsum` branch | low | 0 (landed) |
| P12 | MASQUE (H2/H3) carrier | real HTTP/2 or HTTP/3 `CONNECT-UDP`/`CONNECT-IP` tunnel to a MASQUE proxy | Irancell/MCI where MASQUE and WARP pass while other methods are upload-throttled | unknown; medium (proxy-limited) | new carrier (`wat/carrier_masque.go`): `http2.Transport` + extended CONNECT (RFC 9298, RFC 9484), PSK/Privacy-Pass auth, datagrams over capsule protocol | medium: needs Cloudflare Privacy Proxy/WARP credentials, new wire format, version gate | 800–1500 LOC |
| P13 | WARP-over-WireGuard carrier | real WireGuard to a WARP endpoint | same as P12 | WARP line speed, unknown in Iran | reuse `golang.zx2c4.com/wireguard`; registration flow (wgcf-style) | medium: dependency + registration, blocked endpoints rotate | 500–900 LOC |
| P14 | QUIC/H3 anywhere | — | blocked/throttled in Iran; Initial is decryptable by design (`RESEARCH.md` §1.6) | none | do not build | — | — |
| P15 | Inbound-only fake (server → client) | Kharej sends a forged ServerHello/cert packet to the client from an allowlisted source | DPIs that also classify the server→client direction (TSG-class parsers parse both directions, [bbs #653](https://github.com/net4people/bbs/issues/653)) | none | needs a raw sender on Kharej (server has no CAP_NET_RAW requirement today) and the same flow key; cannot help an outbound SNI allowlist | high: needs server-side raw sockets, source-IP spoofing, and the client kernel drops the packet; no field evidence | — |
| P16 | Cloudflare front / clean IP (no engine work) | real dial to `188.114.x.x`/`2a06:98c1::`/`2606:4700::` with SNI+Host = the Cloudflare-proxied name | MCI (IPv6) / Irancell (IPv4) | line speed if the CF leg is not the bottleneck; `REPORT.md` shows the CF handshake works but data stalls on the tested path | config/manager preset: `carrier: wss`, `peer: <CF edge>:443`, `sni: <zone>`, `host: <zone>`, `fp: chrome`, `-ech off`; IPv6 variant needs P5's host-side connectivity only (no fake-SNI) | low: existing code; needs a domain/worker; CF terms/abuse risk | 0 LOC (docs/manager only) |

### 6.1 Status of the parallel task-2 implementation round (working tree, 2026-10-22)

The task-2 round landed `split`, `hlen0`, `fakeip`, `synrst` and `all` in `wat/desync.go` while this brief was being
written. Graded against the wire behaviour derived above:

| Landed mode | What it actually does | Grade vs. the field recipe | What to do next |
|---|---|---|---|
| `split` (`splitHello`, default 3, 2..16) | cuts the fake hello at byte 1 and at the `server_name` extension boundary, then divides evenly; seq concatenates below the stream start | **P2 only** (plain TCP segmentation): no TLS record is re-framed, so a DPI that parses per record (instead of per segment) sees the original hello. Useful against per-segment triage, identical to `seq` against a reassembler | keep; it is cheap and orthogonal. Do not expect it to beat a record-reassembling DPI |
| `hlen0` (`fakeHelloZeroRecord`) | zeroes the 5-byte record length, keeps the body after it | **half of P1, and not the F&F shape**: the field recipe emits *valid* record headers with tiny payloads (0, 104, then 1 byte), never a lying length. A strict record parser will read the body's first bytes (`01 00 00 …`) as a new record header (invalid type) and bail — that *may* be the desired fail-open, but it is a different signal from F&F and a length-ignoring per-packet sniffer still reads the SNI from the body | replace/extend with the true record plan (P1) — `recordReframe` + `fakeSegs`; keep the current marker as an additional variant for A/B if cheap |
| `fakeip` | SYN + ClientHello from the same client port to `cfg.FakeIP` (default 104.16.0.1:443) | **P7**: different 4-tuple, so it cannot whitelist the real flow on a 5-tuple DPI (§5.2). It is the cleanest possible test of the degenerate-key hypothesis, and nothing more | keep behind an explicit flag, never in `auto`, and log loudly that it is experimental |
| `synrst` | in-window SYN\|RST, damaged checksum | **P6**: plausible harder flow-table clear than `rst`; SYN\|RST is an illegal flag combination, so an ISP IPS may flag it as an anomaly (medium risk) and a checksum-validating NAT would let it reach the server and tear down the real connection | keep; document the same caveat as `rst`; do not ship enabled by default |
| `all` | seq + sum + hlen0 markers 1 ms apart | **P11**: useful A/B kitchen sink; no new mechanism beyond its parts | keep for field A/B; do not make it the default |

Still missing from the field recipe: the true record plan (P1: empty + 104 B + 1-byte records, then the 114/1-segment
TCP plan), the real-hello variant (P3), `-tls-min 1.2` + `-tls-ciphers` (P4) and IPv6 (P5). §8 remains the plan for
those.

---

## 7. Dead ends on this evidence

- **`tls-frag` (TCP-level fragmentation of the real hello) as the F&F substitute**: it does not change record
  headers, so a TCP-reassembling DPI sees the untouched ClientHello. Iran's upgraded DPI reassembles
  ([bbs #628](https://github.com/net4people/bbs/issues/628)); a reporter says fragmented tlshello stopped passing
  ([bbs #640](https://github.com/net4people/bbs/issues/640)). Keep `tls-frag` for old segments only.
- **ECH on MCI/Irancell** now: the front domain is filtered **[field intel]** and the recipes explicitly clear
  `echConfigList`. Do not gate the next release on ECH.
- **QUIC/H3 camouflage**: QUIC Initial is decryptable by design, and QUIC is blocked in the field
  (`RESEARCH.md` §1.6). No.
- **Fake SNI of a domestic domain toward a foreign IP** (`mci.ir` → Hetzner): SNI and destination disagree; if any
  cross-check exists this is the worst case, and `RESEARCH.md` Part 13 records field failures of exactly this
  shape. Prefer a CDN-hosted SNI when dialing the CDN.
- **`fakeip` as a whitelisting mode**: see §5.2 — different flow key, no collision.
- **More fake-hello realism** (`ECH GREASE`, browser extensions): the fake already imitates Chrome better than most,
  and the fact that F&F (record/segment shape) is what works on Irancell while fingerprint-only methods are
  upload-throttled points at shape triage, not JA4 realism. Spend effort on P1–P4 before more hello cosmetics.

---

## 8. Implement next (prioritized, ≤5)

Order chosen so each item can be field-tested alone and none of them can break existing deployments.

### 1. True F&F record plan for the **fake** hello (P1) — **~1 day, ~100 LOC + tests**
- **Why first:** the task-2 round landed `split` and a length-zero `hlen0`, but neither emits the field recipe's
  record stream (valid headers of 0/104/1 bytes) nor its 114/1 TCP plan. This is the only way to exercise the
  record-triage diagnosis in §3.3 without touching the real handshake; the server never parses the fake.
- **Files:** `wat/desync.go` (extend `hlen0` or add `fragrec`: `recordReframe(hello, 0, 104, 1)`,
  `fakeSegs(r, []int{114, 1}, 11)`; loop in `fireLocked`), `wat/desync_test.go` (record structure, concatenation,
  seq arithmetic, 11-piece plan, old modes byte-identical), `cmd/wattun/main.go` (only if a new mode name is used).
- **Acceptance:** for a synthetic 300-byte hello, the test parses the sent packets back and asserts:
  each packet's TCP payload begins with `16 03 01`, the first record length is 0, the second is 104, the rest are 1,
  the concatenated record payloads equal the original hello bytes, every seq < base, every checksum valid, and the
  pre-existing `seq/sum/seqsum/rst` tests are byte-identical.
- **Test first on:** the local DPI emulator with a "first-record SNI parser" rule (§9) — it must flip from
  `block` to `pass` with `fragrec` and stay `pass` with a full-reassembly rule (where the honest expectation is
  `block`, proving the emulator is not cheating).

### 2. `-tls-frag-rec` for CDN legs only (P3) — **~1 day, ~120 LOC + tests**
- **Why second:** it is the literal F&F reproduction and the only item that can fix the *real* handshake on an
  Irancell-class path whose DPI parses the first record; but it is only safe where the TLS peer tolerates the empty
  record (Cloudflare edge), so it must be opt-in and documented as CDN-only.
- **Files:** `wat/tlsfp.go` (`newRecordFragConn`, wire into `handshake1`), `wat/tlsfp_test.go` (a local Go TLS
  server must reject it — pin that with a test that asserts the failure, so nobody enables it by default; a second
  test with a hand-written tolerant server confirms the bytes), `docs/TECHNICAL.md` (flag, risk).
- **Acceptance:** with a fake tolerant server, the first flight is exactly the F&F plan; with a Go server the
  handshake fails with `unexpected_message` (pinned by test); flag default off; `-fp go` and `-fp chrome` both work.
- **Gate:** do not advertise it for direct `tls` peers; the manager must not set it for a non-CDN peer.

### 3. `-fp unsafe` (alias of `go`) + `-tls-min 1.2` + `-tls-ciphers` on the stdlib path (P4) — **~3 h, ~60 LOC + tests**
- **Why:** completes the Irancell F&F fingerprint half once the record half exists; also gives testers a way to
  reproduce the recipe exactly.
- **Files:** `wat/carrier_tls.go` (`TLSClientOptions` fields, `config()`), `wat/tlsfp.go` (validation/normalisation,
  `unsafe`→`go`), `cmd/wattun/main.go` (flags), `docs/TECHNICAL.md`.
- **Acceptance:** `-fp unsafe` is accepted and equals `go`; `-tls-ciphers` with an unknown name errors like other
  flags; with `-tls-min 1.2` the generated ClientHello (parsed in a test) contains the configured 1.2 suites
  intersected with Go's supported set, plus the three 1.3 suites; with the default 1.3-only config the flag is
  documented as no-op (assert no regression).

### 4. IPv6 parity for the fake-SNI layer (P5) — **~2 days, ~250 LOC + tests**
- **Why:** MCI's best route is IPv6-only in the field intel; today Wattunnel's injector silently does nothing on a
  v6 flow, so a test there would be meaningless.
- **Files:** `wat/desync.go` (`desyncKey6`, `fakePacket6`, `handleIPv6`, `parseEthIPv6`), `wat/desync_linux.go`
  (raw6 socket + send, `parseEthIPv6` in the loop, peer v6 accept), `wat/desync_test.go` (checksums over the IPv6
  pseudo-header, key symmetry, unchanged v4 behaviour), `cmd/wattun/main.go` (peer brackets already handled by
  `SplitPeers`), `docs/TECHNICAL.md`.
- **Acceptance:** unit tests pin IPv6 header fields, TCP checksum, flow-key direction, and that a v6 `Wrap` now
  announces instead of passing through; v4 tests unchanged; build on Windows (`desync_other.go` unchanged).

### 5. "Clean Cloudflare IP + worker domain" preset (P16) — **~3 h, 0 engine LOC**
- **Why:** it is the MCI recipe and the only item that can work *today* on a route the team already has a Cloudflare
  zone for; it also proves the CDN data-leg bottleneck separately from any desync work.
- **Files:** `wattun-manager` (a "clean Cloudflare IP" preset/wizard page) and `docs/TECHNICAL.md` (a
  "CDN fronting over a clean Cloudflare IP" subsection); no Go change, because `peer`, `sni` and `host` already
  express the recipe.
- **Acceptance:** a stock `wss` client with `peer: 188.114.98.0:443`, `sni`/`host` = the zone, `fp: chrome`,
  `-ech off` reaches the origin (`REPORT.md` §7b already shows `101` works); documented with the exact
  `188.114.96.0/20`, `2a06:98c0::/29`, `104.16.0.0/13`, `2606:4700::/32` ranges and the "IPv6 only if the client
  host has a v6 default route" caveat.

**Deliberately not in the list:** `fakeip` (P7), inbound-only fake (P15), MASQUE/WARP carriers (P12/P13 — large,
new credentials/dependency, separate go.mod work), ECH work, QUIC. They are documented so the next round does not
re-derive them.

---

## 9. How to validate, before any field trip

The `testbench/` work (task-3) must model the five DPI behaviours this brief's hypotheses depend on; otherwise the
results will be meaningless:

1. **Record-triage rule**: parse only the first TLS record of a flow; if it has no SNI, `PASS` (fail-open), and log
   the verdict. `fragrec` must flip this from `BLOCK` to `PASS`.
2. **Segment-triage rule**: parse only the first TCP segment. `split`/`fragrec` must hide the SNI from it.
3. **Full-reassembly rule**: reassemble TCP, concatenate record payloads, extract the SNI. `fragrec` must **not**
   evade this rule (honesty check).
4. **Size rule**: drop a single TLS record/handshake > N bytes (the `REPORT.md` 1474 B observation). `fragrec`'s
   per-record sizes are ≤109 B, so it should pass; TCP-level `-tls-frag` should not.
5. **Allowlist + throttle rule**: allow flows whose SNI is in the list, and upload-throttle non-TLS-looking flows
   after M bytes/seconds (the Irancell **[field intel]** behaviour). `unsafe`+ciphers config vs `chrome` fingerprint
   becomes measurable here.
6. **Flow-key variants**: 5-tuple (baseline), plus a degenerate per-source-port mode, to demonstrate that `fakeip`
   only "works" under the degenerate key — i.e. that it is not evidence for a real DPI.

Then, on the live pair, a single capture per mode (Iran side `tcpdump -i any -w`, Kharej side the same; see
`RESEARCH.md` Part 12 §5 for the two-capture recipe) plus `filter_profile`/counters. Field verdicts to record, per
mode: handshake success, first 1 MB upload rate, first 1 MB download rate, retransmits, and whether the fake was
seen on the Kharej side (it must not be).

---

## 10. Sources

Primary implementation / config sources (all fetched 2026-10-22):

- Xray `finalMask` docs — https://xtls.github.io/en/config/transports/finalmask.html
- Xray `finalmask/fragment` implementation — https://github.com/XTLS/Xray-core/blob/main/transport/internet/finalmask/fragment/conn.go
- GFW-knocker Xray-core (MahsaNG/PattNG core): fingerprint map — https://github.com/GFW-knocker/Xray-core/blob/main/transport/internet/tls/tls.go ; stdlib fallback — https://github.com/GFW-knocker/Xray-core/blob/main/transport/internet/tcp/dialer.go ; config acceptance — https://github.com/GFW-knocker/Xray-core/blob/main/infra/conf/transport_security.go ; ECH test comment — https://github.com/GFW-knocker/Xray-core/blob/main/transport/internet/tls/ech_selfhosted_test.go
- Real F&F configs — https://github.com/patterniha/Serverless-for-Iran ; https://github.com/amiire81/pattng2 ; https://github.com/amiire81/pattng3
- Named preset `pattng-tlshello-0-len`, Firefox cipher list — https://github.com/malekjani/xray-fragment-scanner/blob/main/profiles/pattng-tlshello-0-len.json ; https://github.com/malekjani/xray-fragment-scanner/blob/main/profiles/pattng-real-firefox-cipherSuites.txt
- F&F definition ("Fragment + Fingerprint") — https://github.com/CluvexStudio/ZedSecure/issues/39
- Fragment background for Iranian ISPs — https://github.com/bia-pain-bache/BPB-Worker-Panel/blob/main/docs/en/docs/configuration/fragment.md ; https://github.com/ircfspace/fragment

Protocol / platform sources:

- TLS 1.3, zero-length handshake fragments — https://www.rfc-editor.org/rfc/rfc8446.html (§5.1, §4.2.1)
- ECH — https://www.rfc-editor.org/rfc/rfc9849.html ; SNI — https://www.rfc-editor.org/rfc/rfc6066.html ; GREASE — https://www.rfc-editor.org/rfc/rfc8701.html
- Go `crypto/tls` zero-length handshake record rejection — https://github.com/golang/go/blob/master/src/crypto/tls/conn.go
- Go ClientHello cipher list construction — https://github.com/golang/go/blob/master/src/crypto/tls/handshake_client.go ; https://github.com/golang/go/blob/master/src/crypto/tls/common.go ; https://github.com/golang/go/blob/master/src/crypto/tls/defaults.go
- Cloudflare IP ranges (188.114.96.0/20, 2a06:98c0::/29, 104.16.0.0/13, 2606:4700::/32) — https://api.cloudflare.com/client/v4/ips and https://www.cloudflare.com/ips/
- Cloudflare MASQUE over HTTP/2 and HTTP/3 — https://developers.cloudflare.com/privacy-proxy/concepts/how-it-works/ ; https://blog.cloudflare.com/masque-now-powers-1-1-1-1-and-warp-apps-dex-available-with-remote-captures/
- MASQUE standards — https://www.rfc-editor.org/rfc/rfc9298.html (CONNECT-UDP) ; https://www.rfc-editor.org/rfc/rfc9484.html (CONNECT-IP)
- Cloudflare WARP — https://developers.cloudflare.com/warp-client/ ; https://developers.cloudflare.com/warp-client/get-started/linux/
- GoodbyeDPI (wrong-seq, wrong-chksum, TTL fakes, `--frag-by-sni`, fake ClientHello generation) — https://github.com/ValdikSS/GoodbyeDPI
- zapret (fakes, fooling modes, `fakedsplit`, split markers incl. `sniext`, autottl, badsum, rst, synack) — https://github.com/bol-van/zapret/blob/master/docs/readme.en.md
- patterniha/SNI-Spoofing ("Bypass DPI with IP/TCP-Header manipulation") — https://github.com/patterniha/SNI-Spoofing

Measurement / field sources:

- RandLab, "A Swift Look into the Internet Allowlist in Iran" (SNI filtering layered on IP allowlist; ~half of allowlisted IPs; RSTs) — https://randlab.engineering.ucsc.edu/blogs/iran-allowlist/ and [bbs #630](https://github.com/net4people/bbs/issues/630)
- Iran DPI full TCP reassembly — [bbs #628](https://github.com/net4people/bbs/issues/628) ; fragmentation stopped passing — [bbs #640](https://github.com/net4people/bbs/issues/640)
- Geedge/TSG firewall leak analysis (parseable protocols, DPI architecture) — [bbs #653](https://github.com/net4people/bbs/issues/653)
- ICMP-only path, pps cap, volume-triggered reroute — [bbs #676](https://github.com/net4people/bbs/issues/676)
- In-repo: `REPORT.md` (live path 2026-10-22: small-CH fix, 14,480 B cap, POST blocked, Cloudflare 101 verified),
  `RESEARCH.md` (method research, parts 1–14), `docs/TECHNICAL.md` §Fake-SNI desync.

---

## 11. Implement next — the prioritized list (details and acceptance tests in §8)

| Order | Item | What it buys | Size estimate |
|---|---|---|---|
| 1 | True F&F record plan for the **fake** hello (P1): empty record + 104 B record + 1 B records, then the 114/1 TCP plan — extends the landed `hlen0`/`split` | exercises the field recipe's record-triage trick with zero handshake risk; `split` has landed, `hlen0` only zeroes the length | **~1 day, ~100 LOC + tests** |
| 2 | `-tls-frag-rec` real-hello record reframing in `wat/tlsfp.go`, **CDN legs only, default off** | literal reproduction of the Irancell recipe on Cloudflare-terminated connections; breaks on Go TLS peers, so opt-in | **~1 day, ~120 LOC + tests** |
| 3 | `-fp unsafe` (= `go`) + `-tls-min 1.2` + `-tls-ciphers <13-name list>` on the stdlib path (`wat/carrier_tls.go`, `wat/tlsfp.go`) | completes the Irancell fingerprint half; makes the "semi-python" preset available for A/B | **~3 h, ~60 LOC + tests** |
| 4 | IPv6 parity for the fake-SNI layer (`parseEthIPv6`, `desyncKey6`, `fakePacket6`, raw6 send, v6 peer in `wat/desync.go` + `wat/desync_linux.go`) | MCI's IPv6 route finally reaches the injector; today it silently skips v6 flows | **~2 days, ~250 LOC + tests** |
| 5 | `wss`/`h2` "clean Cloudflare IP + worker domain" preset in `wattun-manager` + `docs/TECHNICAL.md` (`peer`=CF anycast IP, `sni`/`host`=zone, `fp: chrome`, ECH off) | the MCI recipe, usable today with zero engine changes; separates CDN data-leg problems from desync problems | **~3 h, docs/manager only** |

Do **not** ship `fakeip` (different flow key, §5.2), inbound-only fakes (§6 P15), MASQUE/WARP carriers (§6 P12–P13,
large and needs new credentials/dependency) or further ECH/QUIC work on this evidence.

