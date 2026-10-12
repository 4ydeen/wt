<div align="center">

<img src="docs/img/banner.jpg" alt="WatTunnel: stay connected, even when only ping gets through" width="100%">

# 🪁 WatTunnel

**Encrypted Iran ↔ Kharej port forwarding that keeps working when the network is filtered, even when only ping gets through.**

[![Release](https://img.shields.io/github/v/release/JohnWatsoon/WatTunnel?style=flat-square)](https://github.com/JohnWatsoon/WatTunnel/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go)](go.mod)
![Platform](https://img.shields.io/badge/platform-linux%20amd64%20%7C%20arm64-lightgrey?style=flat-square)
[![Telegram Channel](https://img.shields.io/badge/Channel-@WatxDev-26A5E4?style=flat-square&logo=telegram)](https://t.me/WatxDev)
[![Telegram](https://img.shields.io/badge/Contact-@watxox-26A5E4?style=flat-square&logo=telegram)](https://t.me/watxox)

**English** · [فارسی](README.fa.md)

</div>

---

WatTunnel connects an **Iran** server (where your users connect) to a **Kharej** server (outside, where your
service runs) and forwards any TCP or UDP port between them. It is one static binary with no dependencies, plus an
interactive manager for setup, monitoring, diagnosis and updates. It was built for routes where TCP and UDP are cut
and only ICMP echo (ping) passes. The same encrypted session also runs over UDP, TCP, TLS, WebSocket, HTTP/2 and
gRPC, including through Cloudflare, so you can pick whatever your route lets through.

Full reference (every config key, flag, `/stats` field): [docs/TECHNICAL.md](docs/TECHNICAL.md).

## Highlights

- **Works when only ping works.** Nine carriers in one session: `icmp`, `udp`, `tcp`, `tls`, `ws`, `wss`, `h2`,
  `h2c`, `grpc`. Bond several into one link, or use reverse mode when only one side can dial out.
- **Fast on lossy links.** Pacing is delay-based, so random loss does not slow it down. Interactive traffic goes
  ahead of bulk downloads.
- **Survives SNI filtering.** Through Cloudflare with ECH, and the manager finds working edges by itself.
- **One process, every port.** TCP and UDP, ports added or removed live without a restart, per-port stats and quotas.
- **Light and secure.** About 40 MB of RAM for an ICMP tunnel. ChaCha20-Poly1305 with a pre-shared key, and unauthenticated packets get
  no reply.
- **Easy to run.** One-line installer, a one-paste connection token, a multi-tunnel dashboard, a connection doctor,
  auto-heal, update and rollback.

## What's new (latest: 2.4.5)

Update **both** servers for every release below.

- **2.4.5: no more stuck CDN connections.** When one Cloudflare connection stalls, the tunnel now stops using it and
  reconnects it, instead of losing packets into it. Fixes downloads dropping to a few MB/s and 1-second freezes.
- **2.4.4: CPU fix.** 2.4.3 made the sending server (Kharej, for downloads) burn CPU on connections whose users read
  slowly: 40-73 % per thread under load instead of 2-13 %. Fixed. Update right away if you are on 2.4.3.
- **2.4.3: much less RAM.** Connections whose users read slowly no longer hold 4-8 MB each on both servers. A
  production CDN tunnel went from about 800 MB to 75 MB per server.
- **2.4.2: CDN downloads no longer collapse.** When Cloudflare's path is slower than the tunnel, the tunnel now backs
  off instead of flooding it. Sustained downloads stay fast (39 -> 50 MB/s average in the field), and the random
  half-second freezes are gone.
- **2.4.1: no more crawling under real traffic.** TCP-based and CDN tunnels no longer slow to a crawl under bursty
  web traffic.
- **2.4.0: faster single downloads.** Stream windows tune themselves, so one download or upload is faster on
  high-latency paths.

Also new in 2.x: CDN mode through Cloudflare with ECH (2.2), several sessions per tunnel (2.3, default 4 for
TCP-type carriers), `wattun` alone opens the manager, and Auto mode tests every variant from one token.

## Why WatTunnel: speed, CPU and comparisons

On a heavily filtered route the usual tunnels fail in measurable ways:

| Problem on a filtered route | What usual tools do | What WatTunnel does |
|---|---|---|
| TCP and UDP are cut after a few packets | Tunnel dies or flaps | Rides ICMP, which isn't cut |
| 0.2–2 % random loss | TCP-style congestion control halves the speed on every loss | Delay-based pacing treats loss as noise, not congestion |
| Small MTU (~680 bytes) | Fragmentation and black-holed packets | 640-byte datagrams by default |
| SNI filtering of CDN domains | Blocked right after the handshake | Cloudflare with ECH; edges and TLS settings are found automatically |
| One process per port | Server CPU saturates | One process for all ports, batched syscalls |
| Changing ports | Restart drops every user | `ports:` list is hot-reloaded every 3 s |
| Link silently dies | You find out from your users | Live status, connection doctor, auto-heal |

### ICMP: real filtered route (Iran ⇄ Europe, October 2026)

Real VLESS (xray) traffic through each tunnel, same servers, same route. WatTunnel numbers are from version 1.8.0.

| | WatTunnel 1.8.0 | GOST v3 ICMP |
|---|---|---|
| Peak throughput | **~33 MB/s**, the route's maximum | 1.6 - 5.4 MB/s |
| Single connection | **~25 MB/s** | 1.0 - 1.6 MB/s |
| Latency p50 (route's raw RTT is ~40 ms) | **40 - 45 ms**, close to zero added | ~51 ms |
| CPU per MB moved (Iran side) | **0.026 CPU-s** | 0.15 - 0.20 CPU-s (**6 - 7x more**) |
| RAM | **~40 MB** | 50 - 70 MB |
| 120 short TLS requests, 24 parallel | **120 / 120 ok** | - |

The route caps at about 50 - 55k ICMP packets per second (~33 MB/s), and WatTunnel fills it. In production it
carries **250 - 300 real clients** through a single process.

Against other ICMP tunnels on the same route (WatTunnel 1.8.0):

| Tool | How it works | Throughput measured | Notes |
|---|---|---|---|
| **WatTunnel** | Own ICMP transport, one process, 4 lanes, AEAD, batched I/O | **up to ~33 MB/s** | Every port in one process, ~40 MB RAM |
| GOST v3 ICMP | QUIC over ICMP | 1.6 - 5.4 MB/s | 6 - 7x the CPU per MB |
| BackPack (tuned) | ICMP transport | ~6.1 MB/s | Latency p50 102 ms / p95 198 ms |
| Hans | IP-over-ICMP tun device | 1.1 - 3.8 MB/s | Needs a C++ build on both servers |
| WireGuard over pingtunnel | WireGuard inside one pingtunnel UDP session | 0.25 - 2.7 MB/s | Flat ceiling of a single pingtunnel process |
| pingtunnel | One process per port | ~0.5 MB/s under load | Each process reads every ICMP packet, so the CPU saturates |
| ptunnel-ng | One ICMP proxy per port | ~20 KB/s | Last resort only |

### CDN (Cloudflare): field numbers

Real measurements, 2026-10-11, Iran → Cloudflare → Kharej, 2-vCPU servers, `wss` + ECH:

| Setup | Result |
|---|---|
| 1 session (2.3.0) | ~19 MB/s down |
| 4 sessions (2.3.0) | ~52 MB/s down, ~51 MB/s up |
| 6 sessions (2.3.0) | ~60 MB/s down |
| 8 sessions (2.3.0) | peak 69 MB/s up |
| 6 sessions (2.4.0) | 76.6 MB/s up |
| ICMP tunnel on the same path (only ICMP passes directly there) | ~1.1 MB/s down, ~2.1 MB/s up |
| Any CDN variant **without** ECH | did not connect at all |

We did not measure competitors' CDN speeds on this route, so there is no speed comparison here, only a feature one:

| | WatTunnel | Typical manual CDN setup (a ws/grpc proxy behind Cloudflare, configured by hand) |
|---|:-:|:-:|
| Cloudflare carriers (`ws`/`wss`/`grpc`) | ✅ | ✅ |
| ECH against SNI filtering, config fetched automatically | ✅ | ❌ by hand |
| Automatic scan for working Cloudflare IPs | ✅ | ❌ by hand |
| Automatic choice of TLS fingerprint / ECH / fragmentation by speed test | ✅ | ❌ by hand |
| Several sessions per tunnel, spread over several Cloudflare IPs | ✅ (default 4) | ❌ by hand |
| Ports added or removed without a restart | ✅ | depends on the tool |
| Auto-heal re-tests and replaces dead Cloudflare IPs | ✅ | ❌ |

### Feature comparison

| | WatTunnel | GOST | pingtunnel | Hans | ptunnel-ng |
|---|:-:|:-:|:-:|:-:|:-:|
| ICMP carrier | ✅ | ✅ | ✅ | ✅ | ✅ |
| UDP / TCP / TLS / WS / gRPC carriers | ✅ | ✅ | ❌ | ❌ | ❌ |
| Cloudflare/CDN with ECH | ✅ | - | ❌ | ❌ | ❌ |
| Auto mode: one token tests every variant | ✅ | ❌ | ❌ | ❌ | ❌ |
| Loss-tolerant (delay-based) pacing | ✅ | ❌ | ❌ | ❌ | ❌ |
| All ports in one process | ✅ | ✅ | ❌ | ✅ (tun) | ❌ |
| Add or remove ports without restart | ✅ | ❌ | ❌ | - | ❌ |
| UDP port forwarding | ✅ | ✅ | ⚠️ | ✅ | ❌ |
| Built-in encryption | ✅ AEAD | ✅ | ⚠️ | ⚠️ | ❌ |
| Adaptive FEC | ✅ | ❌ | ❌ | ❌ | ❌ |
| Per-port traffic stats and quotas | ✅ | ❌ | ❌ | ❌ | ❌ |
| Reverse mode (TCP-based carriers) | ✅ | ✅ | ❌ | ❌ | ❌ |
| Reverse ICMP (Kharej pings, Iran keeps the ports) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Single static binary, no dependencies | ✅ | ✅ | ✅ | ❌ | ❌ |
| Guided manager, token pairing, auto-heal | ✅ | ❌ | ❌ | ❌ | ❌ |

**Honest note.** On a clean emulated link (20 ms each way, 0.2 % loss, 100 Mbit) every tunnel reaches line rate and
GOST uses a little less CPU, but WatTunnel halves small-request latency (p50 **43 ms vs 83 ms**) because it sends
interactive streams first. WatTunnel's big advantage is on lossy, filtered routes. These numbers come from specific
routes; yours will differ, so run `wattun test NAME`. Full table: [bench/results-2026-10-09-final.md](bench/results-2026-10-09-final.md)
and [docs/TECHNICAL.md](docs/TECHNICAL.md#why-it-exists).

## Quick start

You need two Linux servers with systemd (amd64 or arm64) and root. **Set up Kharej first**, because it creates the
token that Iran needs.

**1. Install on both servers**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
```

<details>
<summary>GitHub is blocked on the server?</summary>

```bash
WAT_PROXY=https://ghproxy.net/ bash <(curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
```

Or download `wattun-linux-amd64`, `install.sh` and `wattun-manager` from the
[releases](https://github.com/JohnWatsoon/WatTunnel/releases) page and copy them over. Put the binary in `dist/`
next to `install.sh` and run `bash install.sh`.
</details>

**2. Kharej (outside), do this first.** Run `wattun`, press `n` (new tunnel) and choose **Kharej**. Pick a connection
type (see below; `auto` is a good start). You get a **token**:

```
wat1:aWNtcHwyMDMuMC4xMTMuMTB8a1E3...
```

**3. Iran (inside).** Run `wattun`, press `n`, choose **Iran**, answer yes to "Do you have the token?" and paste it.
Then enter the ports your service uses, for example `443, 8443:443, 53/udp`. `8443:443` means users connect to Iran
port 8443 and reach your service on Kharej port 443.

```
   #  Iran port (users)        Kharej port (service)   proto
   1  443                 ──►  443                     tcp
   2  8443                ──►  443                     tcp
   3  53                  ──►  53                      udp
```

```
  ✔ Writing key and config
  ✔ Starting wattun@iran
  ✔ CONNECTED (RTT 41.3 ms)

  users ──► Iran :8443 ══ icmp ══► Kharej ──► 127.0.0.1:443
```

Users now connect to the Iran server's IP. Kharej only ever forwards to its own `127.0.0.1`.

## Choosing a connection type

| Your situation | Use | Notes |
|---|---|---|
| Only ping passes | `icmp` | Needs root. `icmp-type` can be `echo`, `timestamp`, `info` or `mask`. |
| UDP works | `udp` | Lowest latency and CPU. |
| Plain TCP works | `tcp` | A pool of connections. |
| Traffic should look like HTTPS | `tls` | TLS 1.3. Set `tls-pin` to pin the certificate. |
| Through a CDN | `wss` or `grpc` | See [Cloudflare mode](#cloudflare-cdn-mode). `ws`/`h2c` are for a CDN on port 80 or a proxy that handles TLS. |
| Iran can't ping Kharej, but Kharej can ping Iran | `icmp` + [reverse](#reverse-mode) | Kharej sends the pings, Iran answers. |
| Iran can't reach Kharej's TCP port, but Kharej can reach Iran | TCP-type carrier + [reverse](#reverse-mode) | Iran listens, Kharej dials. |
| Don't know | `auto` | See [Auto mode](#auto-mode). |
| Must survive any one carrier being blocked | Bonding, e.g. `carrier: icmp+udp+tcp` | [docs/TECHNICAL.md#bonding](docs/TECHNICAL.md#bonding) |

If the route cuts TCP in both directions, only ICMP (and reverse ICMP) will do.

### Reverse mode

Reverse swaps who starts the connection. Users still connect to Iran, and traffic still goes to your service on
Kharej. Reverse ICMP is for Iran IPs that are blocked one way: `ping KHAREJ_IP` fails on Iran but `ping IRAN_IP`
works on Kharej. Both servers need 2.0.0 or newer.

1. Update both servers.
2. **Kharej:** `wattun` → open the tunnel → `o` (advanced) → `d` (direction). Enter Iran's IP and confirm the restart.
3. **Iran:** the same keys, confirm the restart. Then run `wattun test NAME` on Kharej.

For a new tunnel, pick reverse in the Kharej wizard's advanced settings: the token carries it. By hand:

```yaml
# Kharej: /etc/wattun/kharej.yml
mode: server
carrier: icmp
reverse: true
peer: 198.51.100.20     # Iran's IP: Kharej sends the pings here
```

```yaml
# Iran: /etc/wattun/iran.yml
mode: client
carrier: icmp
reverse: true
peer: 203.0.113.10      # Kharej's IP, as before
```

Reverse also works for the TCP-type carriers (Iran listens, Kharej dials Iran's `IP:port`, 1.8.0 or newer). `udp` has
no reverse mode. Details, certificates, and what to keep in mind:
[Reverse ICMP](docs/TECHNICAL.md#reverse-icmp), [Reverse pool carriers](docs/TECHNICAL.md#reverse-pool-carriers).

## Auto mode

Not sure what works on your route? Pick `auto` as the carrier in the Kharej wizard. One bonded tunnel listens on every
carrier at once and prints one token. Paste it on Iran, and the manager tests each variant (direct, then through
Cloudflare if you gave a domain, then reverse) with a short speed test, in about 2 to 3 minutes. It shows a table
ranked by download plus upload: **Enter** uses the best, **b** bonds the working ones, **1-N** picks one.

Re-run it with `wattun auto-test NAME`. If the reverse side cannot learn Iran's IP, run `wattun auto-ip NAME IRAN_IP`
on Kharej. Auto-heal can switch to another working carrier by itself. Kharej needs 2.1.0 or newer. Details:
[docs/TECHNICAL.md#auto-mode](docs/TECHNICAL.md#auto-mode).

## Cloudflare (CDN) mode

For routes where only HTTPS to a CDN gets out, or the filter looks at the SNI.

1. Put a domain on Cloudflare, with the proxy (orange cloud) on and SSL mode **Full**. For `grpc`, turn on gRPC in
   Cloudflare's Network settings if your plan shows that switch.
2. In the Kharej wizard choose `wss` (or `grpc`) and enter the domain. `h2` does not work through Cloudflare, and
   plain `ws` on HTTP ports can hang at the upgrade.
3. On Iran, the manager finds the ECH config by itself and scans Cloudflare edge IPs for ones that really work for
   your domain. It then tests the Chrome fingerprint, ECH, plain TLS and ClientHello fragmentation, and writes the
   winner to the config.
4. Use several `sessions` (default 4) to fill the pipe. Re-tune any time with `wattun cdn-tune NAME`. Auto-heal
   replaces dead edges.

Manual keys (`fp`, `ech`, `tls-frag`, several `peer` addresses) and troubleshooting: [docs/TECHNICAL.md#cdn-tuning](docs/TECHNICAL.md#cdn-tuning).
More on sessions: [docs/TECHNICAL.md#several-sessions-230](docs/TECHNICAL.md#several-sessions-230).

## Managing tunnels

Run `wattun` for the dashboard of all tunnels (`wattun-manager` still works). Press a tunnel's number to manage it,
`n` for a new one, `m` for the live monitor, `u` to update, `s` for settings (rollback, uninstall, auto-heal), `q` to
quit. A tunnel's page has diagnose and speed test, logs, port-mapping editor, token, advanced settings, restart,
and delete. The doctor names the likely cause when a link is down.

```bash
wattun                 # dashboard
wattun new kharej      # new tunnel (kharej or iran); do Kharej first
wattun status          # one line per tunnel
wattun monitor         # live dashboard
wattun ports NAME      # edit the port mappings of a tunnel
wattun test NAME       # connection doctor + speed test
wattun speedtest NAME  # speed test only (10 MB each way)
wattun logs NAME       # follow the log
wattun token NAME      # print the Kharej token
wattun auto-test NAME  # re-run the Auto mode test
wattun cdn-tune NAME   # re-tune a Cloudflare tunnel
wattun auto-ip NAME IP # tell an auto tunnel Iran's IP (on Kharej)
wattun update | rollback | help
```

**Config.** Each tunnel is `/etc/wattun/NAME.yml`, run by systemd as `wattun@NAME`. Keys are the flag names. Only the
`ports:` list reloads live (within 3 seconds); anything else needs `systemctl restart wattun@NAME`.

```yaml
# /etc/wattun/iran.yml
mode: client
key-file: /etc/wattun/iran.key
carrier: icmp
peer: 203.0.113.10
metrics: 127.0.0.1:19750
ports:
  - 443          # users connect to Iran :443, delivered to Kharej 127.0.0.1:443
  - 8443:443     # users connect to Iran :8443, delivered to Kharej 127.0.0.1:443
  - 53/udp
  - 5353:53/udp
```

On Kharej, `ports:` is an allowlist of target ports (leave it out to allow any). Every key:
[docs/TECHNICAL.md#config-file](docs/TECHNICAL.md#config-file).

**Auto-heal.** A systemd timer (`wattun-heal`) restarts an Iran tunnel whose link has been down for 3 minutes. It is
turned on for Iran tunnels automatically (off: `wattun` → `s` → `h`) and does not restart a tunnel you stopped.

## Monitoring

Each tunnel serves a small HTTP API on `127.0.0.1` only (never expose it):

```bash
curl -s 127.0.0.1:19750/stats       # alive, last_rx_age_ms, srtt_ms, rate_bps, loss_pct, streams, sessions, bytes...
curl -s 127.0.0.1:19750/ports       # traffic per port
curl -s '127.0.0.1:19750/speedtest?dir=down&mb=10'   # built-in speed test (client side)
```

Use `last_rx_age_ms` rather than ping to judge a link's health. Field reference:
[docs/TECHNICAL.md#metrics](docs/TECHNICAL.md#metrics).

## Security

- The pre-shared key is never sent. Each session derives its own key and every packet is sealed with
  ChaCha20-Poly1305. A packet that does not authenticate gets no reply, so scans see nothing.
- Kharej only forwards to its own `127.0.0.1`, and only to allowed ports. The metrics address is forced to `127.0.0.1`.
- `/etc/wattun` is mode `700` and key files `600`. **The token contains the key**, so share it privately.
- WatTunnel encrypts and authenticates your traffic. It does not hide that a tunnel exists, and it is not an
  anonymity tool.

## Troubleshooting

Start with `wattun test NAME`. Then `systemctl status wattun@NAME` and `journalctl -u wattun@NAME -f`.

| Symptom | Likely cause and fix |
|---|---|
| `DISCONNECTED`, or the log says `no reply from the server` | Different key or carrier on the two sides: paste the token again on Iran. For ICMP, check that Iran can ping Kharej, and run the doctor. |
| Iran can't ping Kharej, but Kharej can ping Iran (often one day yes, one day no) | One-way block. Switch both sides to [reverse ICMP](#reverse-mode). |
| Works some days only | The route is filtered on the bad days. Keep auto-heal on and a second tunnel with another carrier as a backup. |
| `tcp`, `tls` or `ws` never connect, or a CDN tunnel connects and then stalls | That carrier is filtered. Try `icmp`, or `wss` through Cloudflare, and run `wattun cdn-tune NAME full`. |
| Connected, but users can't open sites | Nothing listens on Kharej's `127.0.0.1:PORT`. |

More (`address already in use`, `restart needed for KEY`, MTU, CDN errors):
[docs/TECHNICAL.md#troubleshooting](docs/TECHNICAL.md#troubleshooting).

## Building from source

Go 1.26 or newer:

```bash
git clone https://github.com/JohnWatsoon/WatTunnel && cd WatTunnel
go test ./...
sh build.sh                     # dist/wattun-linux-amd64 and -arm64, each with a .sha256
sudo bash install.sh            # installs the binary you just built
```

Issues and pull requests are welcome. A change that makes the ICMP path slower won't be merged.

## Links

- Reference: [docs/TECHNICAL.md](docs/TECHNICAL.md)
- Telegram channel (news and releases): [@WatxDev](https://t.me/WatxDev), developer: [@watxox](https://t.me/watxox)
- Bugs: [issues](https://github.com/JohnWatsoon/WatTunnel/issues)
- License: [MIT](LICENSE). Uses `golang.org/x/crypto`, `x/net` and `x/sys` (BSD-3-Clause). GOST, Backhaul and BackPack
  were studied for ideas and as benchmarks; no code was copied.
