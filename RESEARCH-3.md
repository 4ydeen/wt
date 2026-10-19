# RESEARCH-3: state of the art after the 2026 upgrades — what is patched, what is new, what fits WatTunnel

Status: research round 3 for branch `dev` (after 2.7.0/2.7.1). Trigger: patterniha's announcement
(two new SNI-Spoofing methods tested successfully against the *updated* firewall of every network he
could reach; neither is runnable on non-root Android; will ship as a standalone exe on
`127.0.0.1:40443` only if a full restriction returns while at least one Cloudflare-CDN domain stays
open). The two methods are **not public** — the SNI-Spoofing repo (last push 2026-04-14) still ships
only `wrong_seq`, with a `wrong_checksum` branch commented out — so this round researched everything
else public instead. Sources: cloned repos (SNI-Spoofing, zapret, GoodbyeDPI, Aether/PattNG,
whitelist-bypass-iran, MMDF) and the net4people/bbs API (issues 618, 628, 630, 640, 648, 649, 650,
653, 654, 660, 669, 673, 675, 676 with comments). Web search still unavailable; GitHub REST via
git's curl worked.

## 0. The honest answer to "are our methods already patched?"

Partly, per method:

| WatTunnel method | Field status (Oct 2026) | Source |
|---|---|---|
| fake-SNI `seq` | Not globally patched. The allowlist study found SNI filtering applied on only ~half of allowlisted source IPs, random never-registered SNIs pass freely, and no residual blocking after an RST. But the January wave killed it on some ASNs via seq normalization. | bbs #630 |
| fake-SNI `ttl` | No field reports of TTL normalization yet; `fake-ttl: 0` auto-calibration keeps it viable. | — |
| fake-SNI `sum` (2.7.1) | Unpatched by construction: bad-checksum fakes fail only behind checksum-validating NATs (rare on Iranian ISPs per zapret's field notes). | zapret docs |
| `tls-frag` (real-hello fragmentation) | **DEAD on the paths where the upgrade deployed**: "GFW drops all fragmented tlshello packets" (#640), and the DPI now reassembles TCP fragments to extract SNI from VLESS/WS+CDN setups, with DNS hijack to 10.10.34.34 and RST floods after (#628). Contested: another reporter still sees fragmentation working ("it would cost them too much to upgrade everywhere") — consistent with the #630 finding that enforcement is per-IP/per-segment, not global. | #640, #628 + comments |
| ICMP carrier | Still the backbone: only ICMP passes on several routes since early Oct 2026; 1500 B restored; ~50k pps / ~30 MB/s ceiling with volume-triggered reroute — network limits, not code. | #676 |
| CDN + ECH (`wss/h2/grpc`) | Works where CDN is reachable: 44–48 MB/s down, 82 up; every non-ECH variant failed. | #676 |

So: our desync family is alive but living on borrowed time in the parts that depend on the censor
NOT validating fields; the parts that depend on the censor not seeing the real bytes at all
(fragmentation) are being actively patched. Anything new should assume **full TCP reassembly,
SNI extraction, checksum/window validation, and behavioral (lifetime/volume) classification** at
the DPI — because that is what the Geedge source leak confirms real products do (#653).

## 1. What everyone else is doing right now (the landscape)

### 1.1 Ride a whitelisted SERVICE, not a fake hello — WebRTC carrier tunnels (the strongest genuinely-new idea)
- **bbs #618** ("Tunneling IP traffic through whitelisted WebRTC carriers"): under IP/SNI/CIDR
  whitelisting, transport-level mimicry loses; traffic must literally BE a whitelisted service.
  Domestic video-call platforms (Bale Meet in Iran, VK/Telemost in Russia) are SFU-mediated
  encrypted media the operator trusts. Two peers run headless Pion; the tunnel rides either an
  SCTP DataChannel or a synthetic VP8 track (no real encoder: two hardcoded frame prefixes + epoch
  + nonce + AEAD ciphertext).
- **Implementations**: `kulikov0/whitelist-bypass` (Russia) and `kulikov0/whitelist-bypass-iran`
  (Bale fork; Android/iOS/Desktop via VpnService + tun2socks; no root needed — this is exactly the
  gap patterniha complained about). ~6.5 Mbps ceiling per VP8 track (fps×batch×1126 B), doubled
  with a screenshare track; DC mode lighter but slower. SFU congestion control punishes pushing
  past per-track limits (it stalls, not drops). Bale's SFU reorders frames enough that the tunnel
  needed a 16-frame reorder buffer to not collapse under TCP.
- **Speed/reliability verdict**: ~6.5–13 Mbps — far below WatTunnel's ICMP 30 MB/s, and dependent
  on a third party's SFU. But it is the only public method that survives a *complete* SNI/IP
  allowlist while staying non-root-Android-viable, and it is invisible by construction (it is a
  video call to a whitelisted domestic service).

### 1.2 Serverless configs (no server at all) — patterniha's `Serverless-for-Iran` (1269★)
Xray-core ≥ 26.6.27 client configs; works because under the 2026 whitelisting many major foreign
services (github, openai, microsoft, google...) are reachable DIRECTLY from Iran. The config:
- routes those services direct (fakedns + geosite lists);
- `tcp-fragment` 1-byte splits (maxSplit 201) and tlshello fragments at byte offsets 6/98/1 and
  0/104/1 (two variants A/B) for everything TLS;
- 24 × 1200–1230-byte random UDP "noise" packets to punch through UDP filters;
- blocks QUIC/UDP-443 and the DNS-hijack IP 10.10.34.34; happy-eyeballs with **IPv6 prioritized**
  (IPv6 is measurably less filtered on mobile).
Speed = line speed for the services that pass; zero infrastructure. Limitation: it is a routing
trick, not a tunnel — no arbitrary foreign site unless it is direct-reachable or frontable.

### 1.3 MMDF — client-side MITM + domain fronting (patterniha; merged into Xray-core via issue 4348)
No server: the client MITMs its own TLS with a locally-installed root cert ("Instant Certificate"),
reads the real Host, then re-originates the request with a FRONT SNI toward CDNs that still permit
fronting (Google, Fastly, Meta; NOT Cloudflare/Cloudfront/Arvan). Declared "unblockable except by
IP block" and it runs on non-root Android **browsers only** (user-cert limitation — plausibly one
of patterniha's two new exe methods is the same family with raw sockets). Big caveats: upstream
cert validation "not performed yet" (a real MITM risk by design), works only for fronting-friendly
services, and trusting a root cert is a security tradeoff WatTunnel should never make silently.

### 1.4 Aether / PattNG (patterniha's Android answer; his actual non-root path)
Rust WARP-class client: **MASQUE over HTTP/3 and HTTP/2** with uTLS-style ClientHello
fragmentation on the H2 leg, `--gool` (WireGuard inside MASQUE), `--mim` (MASQUE inside MASQUE),
"noize" junk-packet profiles (firewall/gfw/aggressive — junk before handshake, between I1, after
handshake, 1–12 ms intervals), automatic endpoint discovery with end-to-end data-plane validation,
Termux installer for non-root Android. It powers PattNG (pushed daily). This is the same family as
our `wss/h2 + ECH` path (44–82 MB/s measured) plus discovery and nesting.

### 1.5 Mimicry pools with lifetime budgets — Hedioum Pool Tunnel (#649)
Go tunnel from inside Iran; the sharpest operational insight in the whole round: after raw volume,
**protocol × connection lifetime is the strongest real-world tell** — "a TLS flow held open for
hours moving tens of GB is anomalous regardless of a perfect handshake". Their countermeasure:
SSH as the long-lived backbone, every other mimic (TLS/SMTP/IMAP/DirectAdmin personas) lives 5–60
min / 1–5 GB then churns; per-install fluctuating mimic distribution; uTLS Chrome hello; active
probes answered by real decoy services; Let's Encrypt certs when a domain exists.

### 1.6 Xray `finalmask` — the industrialized masking framework (v25.10.15 → 26.10, 62+ issues)
Xray turned every classic mask into a composable layer under `finalmask`: `xdns` (DNS-tunnel via
mKCP, client MTU ~130), **`xicmp`** (raw-socket ICMP echo carrier, needs root/CAP_NET_RAW, no MTU
limit since IP layer fragments, developer's own caveat: "still a toy — length alone can kill it";
kernel echo must be silenced like ours), `header-*` (dtls/srtp/utp/wechat/wireguard byte-prefix
masks, 4–13 B overhead), `noise` (UDP junk, the in-stack cousin of our fake), `fragment`, `sudoku`,
`realm` (UDP hole punching), Salamander, Lua-scriptable masks. Also QUIC SNI censorship is now
established in Russia since 2023 (#654) — QUIC Initial is decryptable by design, so QUIC is not a
safe harbor where that hardware deploys.

### 1.7 Russia's mobile whitelist as the mirror (#650, + comments)
Same architecture, instructive failures: whitelist behavior varies per base station and per radio
channel (same phone, same minute, different cell → different policy); hardcoded foreign DNS (8.8.8.8)
breaks even whitelisted sites; public CIDR allowlists are wrong in both directions ("the only check
I trust is a SIM, on the day, against the specific /24" — `vadim-tolmachev/allowlist-probe`);
700+ reserved floating IPs across five cloud regions produced zero known-permitted /24s. Lesson for
Iran: per-segment enforcement is the norm, so per-connection adaptive testing beats any static
allowlist; WatTunnel's `auto` carrier test and manager's variant ranking are the right shape.

### 1.8 Two papers worth knowing
- **#653 Geedge/TSG source leak (USENIX Sec '26)**: first public build-and-run of a real national
  firewall; parseable protocol list and blocking-rule format extracted; usable to test fake-packet
  realism offline. (Iran is a known customer region for such vendors.)
- **#669 Espejismo** (look-like-nothing with masked framing, time-slotted keys, silent reject):
  commenters restate the USENIX '23 GFW result — fully-encrypted "nothing" protocols get classified
  and killed; impersonating real TLS beats looking like nothing. Confirms our carriers' direction.

## 2. What WatTunnel should actually do (ranked, with speed/reliability expectations)

1. **Adopt connection-lifetime/volume churn in the pool layer (cheap, high value, zero wire
   change).** Mirror Hedioum's budgets: recycle a pool connection after N minutes / N GB (client-
   side only, e.g. `pool-rotate: 30m/4GB`), staggered per connection, so no flow looks like a
   months-long TLS pipe. Directly counters the #628 probe-and-block story and #649's field rule.
   Speed cost ≈ 0 (redial at a chosen moment). This is the best speed-per-effort item on the list.
2. **A Bale/WebRTC-style carrier as the whitelist-proof fallback (new code, medium-large).** Not
   for speed (~6.5–13 Mbps) but for the regime nothing else survives: carry the session's
   datagrams over a Bale Meet (or other whitelisted SFU) VP8/DataChannel via headless Pion, as a
   `carrier: bale` option client-side only. Android viability via VpnService+tun2socks is solved by
   the fork we'd learn from. Mark clearly: third-party dependency, TOS/abuse and reliability caveats,
   and it needs the SFU's API surface (join-token-derived keys, no extra auth channel).
3. **Keep hardening fake-SNI, expect the countermove to be behavioral, not packet-shaped.** The
   seq/sum/ttl modes are fine while the censor filters; the #628 pattern (throughput → probe →
   block domain+IP) suggests pairing fake-SNI with item 1's churn and with `sni`+`fp` on the real
   hello (already supported) so the real flow also looks like TLS-to-allowed-site end-to-end.
4. **Do NOT invest in more fragmentation of the real ClientHello.** #640/#628 show the upgraded
   DPI reassembles; our `tls-frag` stays as-is for un-upgraded segments.
5. **QUIC/H3: still NO** (blocked in the field; QUIC SNI filtering exists in Russia and is
   trivially portable — Initial is decryptable by design).
6. **"Look-like-nothing" framing changes: NO** (USENIX '23 + #669 consensus).
7. **Residential-source relays / Starlink sharing: NO on safety grounds** (#675 documents that
   possessing/sharing Starlink access in Iran can carry the death penalty; domestic relay chains
   remain the documented, consented alternative in TECHNICAL.md).

## 3. What patterniha's two unreleased methods probably are (and why we should not chase them)

His statement + repo give three constraints: methods are IP/TCP-header manipulation (the repo's
self-description), they need raw sockets (hence no non-root Android), and one ships as a local
exe with a SOCKS/port listener (127.0.0.1:40443). The commented-out `wrong_checksum` branch (with
`ipv4.ident + 1` next to it) and zapret's fooling taxonomy bound the plausible space: variants of
checksum/seq/ident/IP-fragment fooling on the fake, likely combined (two fakes per connection, the
GoodbyeDPI `--wrong-seq + --wrong-chksum` double-fake pattern). If both were "tested successfully
against the updated firewall of every network", the differentiator is likely **combining foolings
and IP-layer fragmentation of the fake itself** — the fake is discarded by the server anyway, so
fragmenting it costs nothing and defeats DPI fake-reassembly. That is a cheap experiment worth a
`fake-mode`/`fake-frag` knob in our injector (send the fake as 2–3 IP fragments), but it is a
variant of what we have, not a new class; treat as item 3's optional extension after field tests
confirm fake-SNI is being read-then-dropped (the failure signature would be: DPI classifies flow
as blocked despite a valid seq/ttl/sum fake).

## 4. Bottom line

- The patch wave kills **fragmentation of real hellos** and **behavioral anomalies** (lifetime,
  volume, throughput-triggered probing), not yet **field-fooling fakes** nor **ICMP** nor
  **CDN+ECH**.
- The only genuinely new class with real traction is **riding a whitelisted service** (WebRTC/
  Bale), at ~6.5–13 Mbps — an availability fallback, not a speed leader.
- The best speed/reliability plays available to WatTunnel are: keep ICMP (30 MB/s) + CDN/ECH
  (44–82 MB/s) as the primary paths, add **connection churn** to defeat behavioral classification,
  optionally add **fake-IP-fragmentation**, and add a **Bale carrier** as the last-resort whitelist
  survival mode. None of these requires breaking wire compatibility; 1 and 3 are small diffs; 2 is
  the only large one and should be gated on field evidence that ICMP+CDN paths died for a user.

— Written by the round-3 research pass (sources: cloned repos listed in §0; bbs issue numbers cited
inline; all external claims carry their source; no live web was available, GitHub API via git-curl).
