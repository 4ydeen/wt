<div align="center">

<img src="docs/img/banner.jpg" alt="WatTunnel: stay connected, even when only ping gets through" width="100%">

# 🪁 WatTunnel

**Encrypted Iran ↔ Kharej port forwarding that keeps working when the network is filtered, even when only ping gets through.**

[![Release](https://img.shields.io/badge/release-v2.10.12-blue?style=flat-square)](https://github.com/JohnWatsoon/WatTunnel/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go)](go.mod)
![Platform](https://img.shields.io/badge/platform-linux%20amd64%20%7C%20arm64%20%7C%20windows-lightgrey?style=flat-square)
[![Telegram Channel](https://img.shields.io/badge/Channel-@WatxDev-26A5E4?style=flat-square&logo=telegram)](https://t.me/WatxDev)
[![Telegram](https://img.shields.io/badge/Contact-@watxox-26A5E4?style=flat-square&logo=telegram)](https://t.me/watxox)

**English** · [فارسی](README.fa.md)

</div>

---

WatTunnel connects an **Iran** server (where your users connect) to a **Kharej** server (where your service runs)
and forwards any TCP or UDP port between them. One static binary, no dependencies, and a menu that sets everything
up from one pasted token. It rides whatever your route lets through: `icmp` (ping), `udp`, `tcp`, `tls`, `ws`,
`wss`, `h2`, `h2c`, `grpc`, Cloudflare with ECH, reverse mode, several of them bonded into one tunnel, or
fake-SNI desync (`fake-sni`) when the route permit-lists flows by their TLS name (2.6.0; on the wss, h2 and grpc
carriers too since 2.7.0, with automatic TTL calibration, NAT-sequence follow, a checksum mode for routes that
validate sequence numbers (2.7.1), and both markers at once (`seqsum`, 2.8.0); then five more in 2.10.5: `split` cuts the fake hello across segments, `hlen0` is the F&F-style empty TLS record, `fakeip` aims the fake at a whitelisted CDN address (`fake-ip`), `synrst` clears flow tables harder and `all` fires three markers), plus optional `pool-rotate` churn
so no single connection shows a months-stable lifetime (2.8.0; optional byte budget `pool-rotate-bytes`, 2.8.1).
The filter can be probed and the marker mode picked automatically (`fake-mode: auto`, 2.9.0); `wattun blackout
NAME [SNI]` turns the kit on with one command when a censor starts blocking. `tls-small-ch` (2.10.4) keeps the ClientHello at ~250 B (no post-quantum key share) for DPIs that drop large hellos, `ech: ladder` (2.9.0) fetches the
ECH config through the tunnel itself when every public DNS-over-HTTPS server is blocked, and `-governor` (2.9.0)
learns an ICMP path's volume ceiling from its reroute signature.

## Speed

Measured on real Iran ⇄ Europe servers (2 vCPU each), October 2026. Ping is the round trip through the tunnel while
it is fully loaded; the route's own ping is about 40 ms.

| Connection type | Download | Upload | Ping under load |
|---|---|---|---|
| **TCP / TLS / reverse** (2.5.1, production tunnel with users on it) | **195 MB/s (~1.6 Gbit)** | **276 MB/s (~2.2 Gbit)** | 40-51 ms |
| **ICMP** (only ping passes on the route) | **up to ~33 MB/s**, the route's maximum | 26 MB/s | 40-45 ms |
| **Cloudflare CDN** (`wss` + ECH, 4 sessions) | 44-48 MB/s | up to 82 MB/s | 109-116 ms (CDN base 86) |

Plain TCP with no tunnel at all reaches 243 MB/s down on the same route with 16 connections. WatTunnel, encrypted,
reaches **80 % of that**. Full tables, every version and how each was measured:
[docs/TECHNICAL.md](docs/TECHNICAL.md#field-numbers).

### Behind a filter (2.10.12 field test)

Same servers, 2026-10-25, on a route where Iran → Kharej directly is cut about a second into every flow, and Iran →
Cloudflare passes only flows whose TLS name is `www.cloudflare.com`.

| Setup | Result |
|---|---|
| Reverse `tcp` (Kharej dials Iran), with or without `fake-sni` | 36-40 MB/s down, 30-36 MB/s up, 38-46 ms idle |
| `wss` through a Cloudflare edge, real name filtered, `fake-mode: rst` | connected in 2 s (8 of 14 tries): 9-15 MB/s down, 2-5 MB/s up, ~125 ms; 100 MB test 13.8 MB/s down, 4.9 MB/s up |
| the same with any other fake mode, or none | never connected (0 of 23 tries) |

Details and the failures: [docs/TECHNICAL.md](docs/TECHNICAL.md#fake-sni-field-test-21012).

## Compared to other tunnels

Same servers, same filtered route (only ICMP passes), real VLESS traffic through each tunnel:

| Tool | Throughput | Latency p50 | Iran CPU per MB | RAM |
|---|---|---|---|---|
| **WatTunnel** | **up to ~33 MB/s** | **40-45 ms** | **0.026 CPU-s** | **~40 MB** |
| GOST v3 ICMP | 1.6-5.4 MB/s | ~51 ms | 0.15-0.20 CPU-s | 50-70 MB |
| BackPack (tuned) | ~6.1 MB/s | 102 ms | - | - |
| Hans | 1.1-3.8 MB/s | - | - | - |
| WireGuard over pingtunnel | 0.25-2.7 MB/s | - | - | - |
| pingtunnel | ~0.5 MB/s under load | - | CPU saturates | - |
| ptunnel-ng | ~20 KB/s | - | - | - |

That is **about 5x the next best ICMP tunnel, 6-20x GOST at 6-7x less CPU**, and one process carries 250-300 real
users.

| | WatTunnel | GOST | pingtunnel | Hans | ptunnel-ng |
|---|:-:|:-:|:-:|:-:|:-:|
| ICMP carrier | ✅ | ✅ | ✅ | ✅ | ✅ |
| UDP / TCP / TLS / WS / gRPC carriers | ✅ | ✅ | ❌ | ❌ | ❌ |
| Cloudflare/CDN with ECH | ✅ | - | ❌ | ❌ | ❌ |
| One token tests every connection type for you | ✅ | ❌ | ❌ | ❌ | ❌ |
| Loss does not slow it down (delay-based pacing) | ✅ | ❌ | ❌ | ❌ | ❌ |
| All ports in one process | ✅ | ✅ | ❌ | ✅ (tun) | ❌ |
| Add or remove ports without a restart | ✅ | ❌ | ❌ | - | ❌ |
| Reverse mode / reverse ICMP | ✅ / ✅ | ✅ / ❌ | ❌ | ❌ | ❌ |
| Per-port traffic stats and quotas | ✅ | ❌ | ❌ | ❌ | ❌ |
| Guided menu, auto-heal, update and rollback | ✅ | ❌ | ❌ | ❌ | ❌ |

On a clean, unfiltered link every tunnel reaches line rate and GOST uses a little less CPU; WatTunnel still halves
small-request latency there (43 ms vs 83 ms) because interactive traffic goes first.
[Benchmark details](docs/TECHNICAL.md#field-numbers).

## Light when idle

An idle tunnel sends about 2 small packets a second, about 133 bytes/s with headers on `udp` or `icmp`. That is
~11.5 MB a day, or ~345 MB a month. It uses 0.1-0.2 % of one CPU core and 10-17 MB of RAM with no users. A busy ICMP
tunnel with 250-300 users runs in about 40 MB.

Under load, the tunnel adds +0.25 % to the bytes your users move on `tcp` (16 KB packets), and about +5 % on `udp` or
`icmp` with `mtu: 1400`, headers included.

[Idle and bandwidth details](docs/TECHNICAL.md#resource-usage-idle-ram-cpu-and-bandwidth)

## Latest release: 2.10.12

**`fake-sni` now carries a tunnel through a Cloudflare-only whitelist, and anti-censor is a one-key toggle in the manager.**
On the owner's Iran route a `wss` tunnel through a Cloudflare edge connected with `fake-mode: rst` (9-17 MB/s down)
while every other mode and no fake never did. The fake now fires on every pool connection (the old kernel-queue probe
read the wrong queues), a reverse Kharej server can run `fake-sni` too, and `/stats` `alive` is honest. In the
manager, tunnel page `z` turns anti-censor on or off, picks a preset (new first choice: Cloudflare), switches
reverse and sets any single key; off is the plain full-speed tunnel. Only the dialing end needs the update; the
wire is unchanged. This release also ships 2.10.11 (never tagged): the duplicate-ACK wait and a 517-byte Chrome
fake hello. Numbers: [Behind a filter](#behind-a-filter-21012-field-test).

2.10.10 before it: **a tunnel no longer stalls for up to 10 s after a short one-way blackout, and no longer hangs for good when the
Kharej server restarts after one.** Client-side fix: update the Iran server; any 2.10.x Kharej server works with it.

2.10.9 before it was **the first release since 2.5.1: forward secrecy on every session, signed downloads, the anti-censorship kit, and
two bug fixes in the transport.** Old and new versions work together (tested both ways against 2.5.1), so you can
update one server at a time; forward secrecy switches on once both ends run 2.10.0 or newer. Everything in the
anti-censorship kit is client-side, so only the Iran server needs it. This release also fixes a data race in the
receive path and a buffer-reuse bug in bonded tunnels, adds IPv6 support to `fake-sni`, applies `tls-small-ch`
under `fp: chrome|edge` too, and adds `wattun boost` (kernel network tuning) and `wattun matrix NAME` (tries every
anti-censorship combination from the Iran server and applies the best one).
[Full release history](docs/TECHNICAL.md#release-history).

## Setup

You need two Linux servers (amd64 or arm64) with systemd and root. **Set up Kharej first**: it makes the token that
Iran needs.

**1. Install on both servers**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
```

<details>
<summary>GitHub is blocked on the server?</summary>

```bash
WAT_PROXY=https://ghproxy.net/ bash <(curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
```

The proxy is a third-party mirror: it sees and could alter the bytes. `install.sh` therefore checks every download
against an RSA-signed checksum list, with the public key baked into the script, and refuses a mismatch (`openssl`
must be installed; it is everywhere).

Or download `wattun-linux-amd64`, `install.sh` and `wattun-manager` from the
[releases](https://github.com/JohnWatsoon/WatTunnel/releases) page, put the binary in `dist/` next to `install.sh`,
and run `bash install.sh`.
</details>

**2. Kharej.** Run `wattun`, press `n` (new tunnel), choose **Kharej**, and pick **Auto** as the connection type. You
get a token:

```
wat1:aWNtcHwyMDMuMC4xMTMuMTB8a1E3...
```

**3. Iran.** Run `wattun`, press `n`, choose **Iran**, and paste the token. The menu tests every connection type
(about 2-3 minutes) and offers the fastest that works: press **Enter** to take it. Then enter your ports, for example
`443, 8443:443, 53/udp` (`8443:443` means users connect to Iran port 8443 and reach Kharej port 443).

```
  ✔ Writing key and config
  ✔ Starting wattun@iran
  ✔ CONNECTED (RTT 41.3 ms)

  users ──► Iran :8443 ══ tcp ══► Kharej ──► 127.0.0.1:443
```

Done. Users connect to the Iran server's IP, and Kharej forwards only to its own `127.0.0.1`.

**Day to day.** `wattun` opens the dashboard: press a tunnel's number for its page (speed test, diagnose, logs,
ports, change connection type with **m**), `u` updates, `s` holds rollback and auto-heal. Auto-heal is on for Iran
tunnels and restarts one whose link has been down for 3 minutes.

```bash
wattun status          # one line per tunnel
wattun test NAME       # connection doctor + speed test
wattun ports NAME      # edit port mappings (applied live)
wattun update          # update the binary and the menu
```

If you already know what your route allows, you can pick a type yourself in step 2:

| Your route | Use |
|---|---|
| Only ping passes | `icmp` |
| UDP passes | `udp` (lowest latency) |
| TCP passes | `tcp`, or `tls` to look like HTTPS |
| Only a CDN gets out, or SNI is filtered | `wss` through Cloudflare ([CDN setup](docs/TECHNICAL.md#cdn-tuning)) |
| Only Kharej can reach Iran | any of the above with [reverse mode](docs/TECHNICAL.md#reverse-mode) |

## Security

Traffic is encrypted with ChaCha20-Poly1305 under a key derived from the pre-shared key and a random per-session
id; from 2.10.0 the two ends also run an ephemeral X25519 exchange on every session, so traffic recorded before a
later key-file leak stays unreadable. That protects the **Iran ↔ Kharej leg only**: between your users and the Iran
server the traffic is whatever the forwarded service itself provides, so run an end-to-end encrypted protocol
(VLESS+Reality, TLS, WireGuard) inside the tunnel. Kharej dials only its own `127.0.0.1`, and only ports on the
allowlist.
From 2.11.0 no byte of a packet header is constant (the session id and packet number are masked), idle packets are
padded to random sizes with a jittered keepalive, and `udp` has a [reverse mode](docs/TECHNICAL.md#reverse-udp-2110): the Iran
server only listens and never starts a flow towards a foreign address. Raw `tcp` opens with a TLS ClientHello-shaped
hello and masked frame lengths instead of a plain pool id (`tcp-mimic`)
([traffic shape](docs/TECHNICAL.md#traffic-shape-what-a-dpi-sees-2110)).
The installer verifies the download's signature against a public key baked into it, so a `WAT_PROXY` mirror (or
any tampered copy) cannot slip in a changed binary. The connection token contains the key: treat it like a
password and share it only over a private channel. Keep `metrics` on `127.0.0.1`. What stays visible to the
network: the server's address, and the volume and timing of packets. Details:
[security model](docs/TECHNICAL.md#security-model).

## More

Everything else is in [docs/TECHNICAL.md](docs/TECHNICAL.md):
[reverse mode](docs/TECHNICAL.md#reverse-mode) ·
[auto mode](docs/TECHNICAL.md#auto-mode) ·
[Cloudflare / CDN](docs/TECHNICAL.md#cdn-tuning) ·
[bonding](docs/TECHNICAL.md#bonding) ·
[managing tunnels](docs/TECHNICAL.md#managing-tunnels) ·
[config file](docs/TECHNICAL.md#config-file) ·
[monitoring](docs/TECHNICAL.md#metrics) ·
[troubleshooting](docs/TECHNICAL.md#troubleshooting) ·
[security](docs/TECHNICAL.md#security-model) ·
[Windows and building from source](docs/TECHNICAL.md#build-and-test)

- Telegram channel (news and releases): [@WatxDev](https://t.me/WatxDev), developer: [@watxox](https://t.me/watxox)
- Bugs and ideas: [issues](https://github.com/JohnWatsoon/WatTunnel/issues). A change that makes the ICMP path
  slower won't be merged.
- License: [MIT](LICENSE). Uses `golang.org/x/crypto`, `x/net` and `x/sys` (BSD-3-Clause). GOST, Backhaul and
  BackPack were studied for ideas and as benchmarks; no code was copied.
