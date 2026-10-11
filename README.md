<div align="center">

# 🪁 WatTunnel

**A fast, encrypted port-forwarding tunnel that keeps working when the network only lets ping through.**

[![Release](https://img.shields.io/github/v/release/JohnWatsoon/WatTunnel?style=flat-square)](https://github.com/JohnWatsoon/WatTunnel/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go)](go.mod)
![Platform](https://img.shields.io/badge/platform-linux%20amd64%20%7C%20arm64-lightgrey?style=flat-square)
[![Telegram Channel](https://img.shields.io/badge/Channel-@WatxDev-26A5E4?style=flat-square&logo=telegram)](https://t.me/WatxDev)
[![Telegram](https://img.shields.io/badge/Contact-@watxox-26A5E4?style=flat-square&logo=telegram)](https://t.me/watxox)

**English** · [فارسی](README.fa.md)

</div>

---

WatTunnel connects two servers, an **Iran** server (inside) and a **Kharej** server (outside), and forwards any
TCP or UDP port between them. It's a single static binary with no runtime dependencies. One interactive manager
covers setup, monitoring, diagnosis and updates.

It was built for one hard case: a route where **TCP, UDP, GRE, IPIP and ESP are cut after a few packets, and only
ICMP echo (ping) gets through**. Other tools treat that link as a clean TCP pipe and stall. WatTunnel is designed
around it. When the route is less hostile, the same encrypted session also runs over UDP, TCP, TLS, WebSocket,
HTTP/2 or gRPC, including behind Cloudflare.

## Table of contents

- [Highlights](#-highlights)
- [What's new](#-whats-new)
- [Why WatTunnel?](#-why-wattunnel)
- [Benchmarks and comparison](#-benchmarks-and-comparison)
- [Quick start](#-quick-start)
- [The manager](#-the-manager)
- [Auto mode](#-auto-mode)
- [Choosing a carrier](#-choosing-a-carrier)
- [Reverse mode](#-reverse-mode)
- [Configuration](#-configuration)
- [Monitoring and troubleshooting](#-monitoring-and-troubleshooting)
- [Security](#-security)
- [FAQ](#-faq)
- [Building from source](#-building-from-source)
- [License](#-license)

## ✨ Highlights

- **Works when only ping works.** It hides the tunnel inside ICMP echo, timestamp, info or mask messages, with
  640-byte datagrams sized to what filtered routes actually deliver.
- **Fast on lossy links.** Pacing is delay-based, so random loss doesn't slow it down. It has selective acks, fast
  loss repair and optional adaptive FEC. Interactive traffic goes ahead of bulk downloads.
- **Nine carriers, one session.** `icmp`, `udp`, `tcp`, `tls`, `ws`, `wss`, `h2`, `h2c` and `grpc`. You can also
  bond several carriers into one link, or use **reverse mode** when only one side can dial out.
- **Survives one-way ping blocks.** With **reverse ICMP** (2.0.0) Kharej sends the pings and Iran answers, for Iran
  IPs whose own pings get blocked. Users still connect to Iran, and traffic still goes to your service on Kharej.
- **One process for every port.** It forwards TCP and UDP and adds or removes ports **live, without a restart**.
- **Fast and light.** Up to **~33 MB/s over ping alone**, the full capacity of the route, on about 40 MB of RAM and
  6 – 7× less CPU per megabyte than GOST.
- **Encrypted and authenticated.** ChaCha20-Poly1305 with a pre-shared key and per-session keys. Unauthenticated
  packets are dropped silently, so a port scan gets no reply.
- **Easy to run.** One-line installer, a one-paste **connection token**, a multi-tunnel dashboard, a port-mapping
  editor (Iran port ≠ Kharej port), a connection doctor, auto-heal, update and rollback.
- **Observable.** JSON `/stats` with RTT, rate, loss, streams and clients, plus per-port traffic counters and
  quotas.

## 🆕 What's new

**2.2.0: CDN tuning (Iran side only).** Some Iran filters let the TLS handshake through and then black-hole the flow
by the SNI of your domain, or the edges DNS gives you for a zone are degraded while other Cloudflare edges work. When
Iran sets up a CDN tunnel (`wss`, `h2`, `grpc`, `ws`, `h2c` through a Cloudflare domain), the manager now scans about
22 Cloudflare edge IPs, keeps the best 3, then speed-tests a Chrome TLS fingerprint, Encrypted Client Hello (ECH),
plain TLS and ClientHello fragmentation, and writes the winner into the config. No questions. New client keys:
`fp`, `ech`, `tls-frag`, and `peer` accepts several comma-separated addresses. `wattun cdn-tune NAME` re-tunes, and
auto-heal refreshes dead edges. Kharej and the wire format are unchanged. See [CDN tuning](docs/TECHNICAL.md#cdn-tuning).

**2.1.1: just type `wattun`.** The manager now opens with `wattun` (no flags), and `wattun auto-test NAME`,
`wattun token NAME`, `wattun update`, `wattun status` and `wattun auto-ip NAME IP` work too. `wattun-manager` still
works. Fewer questions: Kharej no longer asks which ports Iran may reach (all are allowed; restrict them later in the
port editor), Iran limits the kernel's ping replies by itself when reverse ICMP is used and turns auto-heal on by
itself (off: `wattun` → `s` → `h`), and firewall ports (ufw or firewalld) are opened without a confirm. Auto test
fixes: the table is ranked by download plus upload (ties: lower RTT), the progress lines print correctly, and the
reverse variants start all at once and get up to 45 s to connect (before, most of them failed with "no link in 8 s").

**2.1.0: Auto mode.** Pick `auto` as the carrier in the Kharej wizard and one tunnel listens on every carrier at
once. Paste the single token on Iran and the manager tests each carrier, direct, through Cloudflare and reverse, then
shows a ranked table so you can use the best, or bond the working ones. Auto-heal can switch to another working
carrier by itself. `/stats` on a server has a new `clients` list (IP, carrier, age). Wire-compatible with 2.0.x, but
Kharej needs 2.1.0 for auto. See [Auto mode](#-auto-mode).

**2.0.2: safer metrics, a more reliable manager.** The metrics address is forced to `127.0.0.1`, and the tunnel
refuses to forward to the server's own metrics port. In the manager, changes made in **Advanced settings** are now
applied automatically (before, they were silently never applied, so a direction switch stayed in normal mode).
Diagnose only flags firewall rules that can affect the tunnel (a rule that drops traceroute / time-exceeded is
ignored). Auto-heal no longer restarts a tunnel you stopped, the arrow keys no longer quit the manager, and the
scrollback (with your token in it) is no longer erased. The installer keeps retrying a tunnel that crashes at boot.

**2.0.1: reverse ICMP fix.** Kharej no longer keeps a dead Iran session alive because of the Iran kernel's own echo
copies. `/stats` has a new `last_rx_age_ms`. In reverse mode the manager offers to rate-limit the Iran kernel's own
ping replies, and the `.sha256` files now work with `sha256sum -c`. Also, reverse mode in the manager now covers
every TCP-based carrier, not just ICMP.

**2.0.0: Reverse ICMP.** Some Iran IPs get a one-way block: Iran can't ping Kharej, but Kharej can still ping Iran.
It often comes and goes from day to day. Normal ICMP tunnels (WatTunnel before 2.0.0, Backhaul, Dagger, GOST...) all
die on those days, because Iran is the side that sends the pings. Reverse ICMP swaps only the ping direction: Kharej
sends, Iran answers. Port forwarding does not change. See [Reverse ICMP](#-reverse-mode). Both servers need 2.0.0.

Earlier in the 1.9 series:

- **Port mapping (1.9.0).** Users can connect to a different Iran port than the one your service uses on Kharej
  (`8443:443`). Multi-tunnel dashboard, and the token carries Kharej's allowed ports.
- **Smarter diagnosis (1.9.1 – 1.9.3).** When a tunnel sends but hears nothing back, Diagnose names the cause. It
  pings at four packet sizes, checks whether either server blocks ICMP itself (kernel switch, iptables, nftables),
  and tests the Kharej → Iran direction to tell a one-way block from a two-way one. In 2.0.0 it also suggests reverse
  ICMP when the block is one-way.
- **Hands-off setup (1.9.2).** Press Enter through the wizard and everything is set automatically (name, public IP,
  ports, path). The dashboard is clearer.
- **Reliable updates (1.9.1).** Update says "updated X → Y" or "already up to date", offers to restart tunnels still
  on the old binary, and stats no longer jump backwards when a client disconnects.

## 🤔 Why WatTunnel?

On heavily filtered routes, the usual tunnels fail in measurable ways:

| Problem on a filtered route | What usual tools do | What WatTunnel does |
|---|---|---|
| TCP and UDP are cut after a few packets | Tunnel dies or flaps | Rides ICMP, which isn't cut |
| 0.2 – 2 % random loss | TCP-style congestion control halves the speed on every loss | Delay-based pacing treats loss as noise, not congestion |
| Small MTU (~680 bytes) | Fragmentation and black-holed packets | 640-byte datagrams by default |
| One process per port | Server CPU saturates | One process for all ports, batched syscalls |
| Changing ports | Restart drops every user | `ports:` list is hot-reloaded every 3 s |
| Link silently dies | You find out from your users | Live status, connection doctor, auto-heal |

## 📊 Benchmarks and comparison

### Real filtered route (Iran ⇄ Europe, ICMP only, October 2026)

These are real VLESS (xray) traffic through each tunnel, on the same servers and the same route.

| | 🪁 WatTunnel 1.8.0 | GOST v3 ICMP |
|---|---|---|
| Peak throughput | **~33 MB/s**, the route's maximum | 1.6 – 5.4 MB/s |
| Single connection | **~25 MB/s** | 1.0 – 1.6 MB/s |
| Latency p50 (route's raw RTT is ~40 ms) | **40 – 45 ms**, close to zero added | ~51 ms |
| CPU per MB moved (Iran side) | **0.026 CPU-s** | 0.15 – 0.20 CPU-s (**6 – 7× more**) |
| RAM | **~40 MB** | 50 – 70 MB |
| 120 short TLS requests, 24 parallel | **120 / 120 ok** | – |

The route itself caps out at about 50 – 55k ICMP packets per second (~33 MB/s), and WatTunnel 1.8.0 fills it. In
production it carries **250 – 300 real clients** through a single process.

### Against other ICMP tunnels (same route)

| Tool | How it works | Throughput measured | Notes |
|---|---|---|---|
| **🪁 WatTunnel 1.8.0** | Own ICMP transport, one process, 4 lanes, AEAD, batched I/O | **up to ~33 MB/s** | Every port in one process, ~40 MB RAM |
| GOST v3 ICMP | QUIC over ICMP | 1.6 – 5.4 MB/s | 6 – 7× the CPU per MB |
| BackPack (tuned) | ICMP transport | ~6.1 MB/s | Latency p50 102 ms / p95 198 ms |
| Hans | IP-over-ICMP tun device | 1.1 – 3.8 MB/s | Needs a C++ build on both servers |
| WireGuard over pingtunnel | WireGuard inside one pingtunnel UDP session | 0.25 – 2.7 MB/s | Flat ceiling of a single pingtunnel process |
| pingtunnel | One process per port | ~0.5 MB/s under load | Each process reads every ICMP packet, so the CPU saturates |
| ptunnel-ng | One ICMP proxy per port | ~20 KB/s | Last resort only |

### Feature comparison

| | WatTunnel | GOST | pingtunnel | Hans | ptunnel-ng |
|---|:-:|:-:|:-:|:-:|:-:|
| ICMP carrier | ✅ | ✅ | ✅ | ✅ | ✅ |
| UDP / TCP / TLS / WS / gRPC carriers | ✅ | ✅ | ❌ | ❌ | ❌ |
| Loss-tolerant (delay-based) pacing | ✅ | ❌ | ❌ | ❌ | ❌ |
| All ports in one process | ✅ | ✅ | ❌ | ✅ (tun) | ❌ |
| Add or remove ports without restart | ✅ | ❌ | ❌ | – | ❌ |
| UDP port forwarding | ✅ | ✅ | ⚠️ | ✅ | ❌ |
| Built-in encryption | ✅ AEAD | ✅ | ⚠️ | ⚠️ | ❌ |
| Adaptive FEC | ✅ | ❌ | ❌ | ❌ | ❌ |
| Per-port traffic stats and quotas | ✅ | ❌ | ❌ | ❌ | ❌ |
| Reverse mode (TCP-based carriers) | ✅ | ✅ | ❌ | ❌ | ❌ |
| Reverse ICMP (Kharej pings, Iran keeps the ports) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Single static binary, no dependencies | ✅ | ✅ | ✅ | ❌ | ❌ |
| Guided manager, token pairing, auto-heal | ✅ | ❌ | ❌ | ❌ | ❌ |

### Honest note: clean links

On a clean emulated link (20 ms each way, 0.2 % loss, 100 Mbit), every tunnel reaches line rate. GOST uses a little
less CPU there, and WatTunnel halves small-request latency (p50 **43 ms vs 83 ms**) because it sends interactive
streams first. Full table: [bench/results-2026-10-09-final.md](bench/results-2026-10-09-final.md). WatTunnel's big
advantage is on lossy, filtered routes.

> Numbers come from one real route and one emulated setup. Your route will differ. Use **Live status** to see what
> you actually get.

## 🚀 Quick start

You need two Linux servers with systemd (amd64 or arm64) and root access.

> **The order matters.** Set up **Kharej first**. It creates the **token**. Then set up **Iran** and paste that
> token.

```
  ┌───────────────────────────┐          ┌───────────────────────────┐
  │ STEP 1  Kharej (outside)  │ ─token─► │ STEP 2  Iran (inside)     │
  │ do this one FIRST         │          │ paste the token here      │
  └───────────────────────────┘          └───────────────────────────┘
```

**1. Install on both servers**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
```

<details>
<summary>GitHub is blocked on the server?</summary>

```bash
WAT_PROXY=https://ghproxy.net/ bash <(curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
```

You can also download `wattun-linux-amd64`, `install.sh` and `wattun-manager` from the
[releases](https://github.com/JohnWatsoon/WatTunnel/releases) page and copy them over. Put the binary in `dist/`
next to `install.sh` and run `bash install.sh`.
</details>

At the end, the installer shows the two steps and asks which side this server is
(`1) Kharej, do this first`, `2) Iran, I have the token`, `3) Later`).

**2. STEP 1, Kharej (outside server).** Run `wattun`, press `n` (new tunnel) and choose **Kharej**. Pick a
carrier (`icmp` if only ping works). All ports are allowed, so there is no port question. You get a
**connection token**:

```
wat1:aWNtcHwyMDMuMC4xMTMuMTB8a1E3...
```

**3. STEP 2, Iran (inside server).** Run `wattun`, press `n` and choose **Iran**. Say yes to "Do you have
the token?" and paste it. Enter the ports your service uses (for example `443, 8443:443, 53/udp`). Change the **Iran port** if
users should connect on a different port than your service uses:

```
   #  Iran port (users)        Kharej port (service)   proto
   1  443                 ──►  443                     tcp
   2  8443                ──►  443                     tcp
   3  53                  ──►  53                      udp
```

The manager waits for the link and shows:

```
  ✔ Writing key and config
  ✔ Starting wattun@iran
  ✔ CONNECTED (RTT 41.3 ms)

  Users can now connect to this server:
  users ──► Iran :443 ══ icmp ══► Kharej ──► 127.0.0.1:443
  users ──► Iran :8443 ══ icmp ══► Kharej ──► 127.0.0.1:443
  users ──► Iran :53/udp ══ icmp ══► Kharej ──► 127.0.0.1:53/udp
```

Users now connect to the Iran server's IP. Each Iran port is delivered to its Kharej port on `127.0.0.1`.

> **Iran can't ping Kharej, but Kharej can ping Iran?** Use [Reverse ICMP](#-reverse-mode).

```
users ──► Iran :8443 ══ WatTunnel (icmp / udp / tls / wss …) ══► Kharej ──► 127.0.0.1:443 (your service)
```

## 🧭 The manager

Run `wattun` (version 2.1.1 and newer; `wattun-manager` still works). The first screen is a dashboard of **all** your tunnels:

```
         .
        /|\
       / | \       __        __    _  _____                       _
      <--+-->      \ \      / /_ _| ||_   _|   _ _ __  _ __   ___| |
       \ | /        \ \ /\ / / _` | __|| || | | | '_ \| '_ \ / _ \ |
        \|/          \ V  V / (_| | |_ | || |_| | | | | | | |  __/ |
         `.           \_/\_/ \__,_|\__||_| \__,_|_| |_|_| |_|\___|_|
           `-.     encrypted port forwarding, even when only ping works
  ──────────────────────────────────────────────────────────────────────────
  Dashboard   wattun 2.0.2

   #  NAME          ROLE   CARRIER   STATE           RTT  LOAD
   1  iran          Iran   icmp   ● CONNECTED     41 ms  37 streams
      ↓12.4 GB ↑1.9 GB   ports 443 · 8443→443 · 53/udp
   2  iran-wss      Iran   wss    ● CONNECTED     96 ms  4 streams
      ↓310.2 MB ↑41.0 MB   ports 2053
   3  backup        Iran   icmp   ○ STOPPED
      -   ports 9443→443

  ▸ Press 1-3 to manage a tunnel (status, ports, token, logs, restart)
  ──────────────────────────────────────────────────────────────────────────
  [n] new tunnel   [m] live monitor   [u] update   [s] settings   [q] quit
```

Press a tunnel's number to manage it, `n` to create another one, `q` to quit. Roll back and uninstall are under `s` settings. With no tunnels yet, the dashboard
explains the two steps and offers `n` to create your first tunnel. Everything is single-key, and `Ctrl+C` cancels
the wizard you are in and returns to the menu.

A tunnel's page groups its actions:

```
  ┌─ iran ─────────────────────────────────────────────────────────────────┐
  │ ● CONNECTED   Iran · icmp → 203.0.113.10                               │
  │ rtt 41.3 ms (min 39.8)   rate 1.1 MB/s   loss 0.1%   retrans 12        │
  │ streams 37   clients 1   udp flows 0   ↓12.4 GB ↑1.9 GB                │
  │ Publishes: 443 · 8443→443 · 53/udp                                     │
  └────────────────────────────────────────────────────────────────────────┘
  Status      [d] diagnose + speed test   [v] speed test only   [l] logs
  Ports       [p] edit port mappings
  Connection  [t] paste new token   [a] change Kharej address   [o] advanced settings
  Service     [r] restart  [s] stop  [e] start at boot on/off  [c] edit file
  Danger      [X] delete this tunnel                   [b] back
```

| Feature | What it does |
|---|---|
| **New tunnel** | Guided setup that shows the Kharej-first order. Checks for busy ports (including ports used by your other tunnels), opens the firewall (ufw or firewalld) without asking and generates a random key. Kharej prints a token. Iran asks whether you have it, and explains how to get it if you do not. |
| **Port mappings** | A table editor: `Iran port (users)  ──►  Kharej port (service)  proto`. Type `443, 8443:443, 53/udp, 5353->53/udp`, or add, edit and remove rows by number. It checks ranges, duplicates and busy ports, and warns when Kharej does not allow a target port. |
| **Many tunnels** | Run as many as you like on one server (for example `icmp` as the main and `wss` as the backup). Each has its own name, config file, unit and metrics port, and the manager keeps them from clashing. |
| **Status** | Each tunnel shows `CONNECTED`, `DISCONNECTED` (Iran), `WAITING` (Kharej with no Iran yet) or `STOPPED`, with RTT, streams, traffic and clients. |
| **Live monitor** | All tunnels, refreshed every 2 seconds, with a small history graph of the rate. Any key exits. |
| **Diagnose** | Speed test (10 MB download and upload through the tunnel), plus step-by-step checks: service running, ping or TCP reachability to Kharej, link state, listening ports, whether your service answers on Kharej, and recent errors in the log. Each failure comes with a likely cause. On an ICMP tunnel that is down it also pings Kharej at four packet sizes, checks whether this server itself blocks ICMP (kernel switch, iptables, nftables), and on Kharej can test the Kharej → Iran direction so you can tell a one-way block from a two-way one. When the block is one-way it suggests reverse ICMP. On a reverse tunnel, Kharej pings Iran by itself. |
| **Logs** | Last 100 lines, follow live, problems only, or since the last start. |
| **Token and key** | Show the token again, rotate the key (Kharej), or paste a new token (Iran). |
| **Advanced** | Per tunnel: speed ceiling (`max-mbps`), FEC, bind address, ICMP type, and ICMP **direction** (normal or reverse, key `d`). The wizards also offer name, listen port, URL path and domain/SNI behind a "Change advanced settings?" question. It defaults to no, so pressing Enter keeps the automatic values (name, detected public IP, ports, path). |
| **Auto-heal** | A systemd timer restarts an Iran tunnel whose link stays down for 3 minutes. It is turned on automatically for Iran tunnels (off: `wattun` → `s` → `h`). Restarts are logged as `wattun-heal`. |
| **Update and rollback** | Installs the latest release after checking its SHA-256, with the binary and the manager taken from the same release. It then checks the new version on disk and tells you "updated X → Y" or "already up to date". Running tunnels keep the old binary until they restart, so it lists them and offers to restart them, and the dashboard flags any it missed. The previous binary is kept for a one-step rollback. |

Animations (spinners, the intro, progress bars) turn off by themselves when the output is not a terminal. Set
`WAT_NO_ANIM=1` (or use **Settings**) to switch them off, and `NO_COLOR=1` for plain text.

Command-line shortcuts:

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
wattun update | rollback | help
```

## 🤖 Auto mode

Not sure which carrier works on your route? Let the manager find out (needs `wattun` 2.1.0 or newer and systemd on
Kharej).

1. **Kharej:** New tunnel, and choose `auto` (the first carrier option). You can enter a Cloudflare-proxied domain; it
   is used only to test the CDN carriers (`ws`, `wss`, `h2`, `h2c`, `grpc` through Cloudflare), and it is optional.
   The wizard creates **one bonded server tunnel** that listens on every carrier: `udp` 4443, `tcp` 4443, `tls` 8443,
   `ws` 2052, `wss` 2053, `h2` 2087, `h2c` 2082, `grpc` 2083, plus `icmp`. A busy port moves to a free one. It prints
   one token.
2. **Iran:** paste the token. The test starts by itself, in phases: direct, then CDN (if you gave a domain), then
   reverse. Reverse variants start all at once and get up to 45 s to connect. Each variant is a throw-away client (nothing is published, temp files live in `/run/wattun-auto`) that runs
   a 2 MB down and up speed test. Reverse test ports are opened in the firewall only while their probe runs. It takes
   about 2 to 3 minutes.
3. A table ranked by download plus upload (ties: lower RTT) follows. **Enter** uses the best, **b** bonds the working carriers, **1-N** picks one, **q** quits.
   The normal wizard then continues at port mapping.

Reverse is automatic too. A short-lived watcher on Kharej (`wattun-autowatch-NAME`, one hour at most) waits for Iran's
first test connection, learns Iran's IP and starts a companion tunnel `NAME-r` (reverse ICMP plus reverse dials to
Iran's test ports). If you set a CDN domain, the IP is learned only from `icmp`, `udp`, `tcp` or `tls` clients, because
CDN clients show Cloudflare's address. If it cannot learn it, run `wattun auto-ip NAME IRAN_IP` on Kharej.
`NAME-r` shows on the dashboard as the reverse side of `NAME`, and it is deleted with it.

Re-run the test any time with `wattun auto-test NAME` (the token is kept in `/etc/wattun/NAME.auto`). **Auto-heal**
follows it: after two failed restart cycles on an auto tunnel it re-tests (1 MB, at most once per 30 minutes) and
switches to another working carrier only if the current one fails. It logs `wattun-heal: switched NAME from X to Y`.

Good to know: several ports are open on Kharej at once, and Kharej must run 2.1.0. Details are in
[docs/TECHNICAL.md](docs/TECHNICAL.md#auto-mode).

## 🛰 Choosing a carrier

| Carrier | Use it when | Notes |
|---|---|---|
| `icmp` | **Only ping gets through.** | Needs root (the manager runs it as root). `icmp-type` can be `echo`, `timestamp`, `info` or `mask` if echo is blocked. |
| `udp` | UDP works. | Lowest latency and CPU. |
| `tcp` | Plain TCP works. | A pool of 8 connections. |
| `tls` | The traffic should look like HTTPS. | TLS 1.3, self-signed certificate unless you give one. Set `tls-pin` to pin the certificate. |
| `wss` | Behind **Cloudflare** or another CDN. | Enter your domain during Kharej setup. Turn the Cloudflare proxy (orange cloud) on and set SSL to *Full*. |
| `ws` / `h2c` | A CDN on port 80, or a reverse proxy that handles TLS. | Cleartext to the proxy. The session itself is still encrypted. |
| `grpc` / `h2` | CDNs or proxies that prefer gRPC or HTTP/2. | |

**Behind Cloudflare (2.2.0).** Prefer `wss`, `grpc` or `h2` on a Cloudflare HTTPS port, SSL mode *Full*, and turn on
gRPC in Cloudflare's Network settings for `grpc`. Plain `ws` on HTTP ports can hang at the Upgrade. The Iran side
picks the edge IPs, the TLS fingerprint, ECH and fragmentation by itself (`wattun cdn-tune NAME` repeats it); details
and the manual keys are in [docs/TECHNICAL.md](docs/TECHNICAL.md#cdn-tuning).

Not sure? Start with `icmp` on heavily filtered routes and `wss` behind Cloudflare. If Iran can't ping Kharej but
Kharej can ping Iran, use `icmp` with [Reverse ICMP](#-reverse-mode). If Iran can't reach Kharej's TCP port
but Kharej can reach Iran, see [Reverse mode](#-reverse-mode). Bonding (`carrier: icmp+udp+tcp` joins several carriers into one session that survives any one being blocked),
UDP-only forwards and the other advanced options are covered in
[docs/TECHNICAL.md](docs/TECHNICAL.md#bonding).

## 🔁 Reverse mode

Reverse mode swaps who starts the connection. It works for ICMP (2.0.0) and for the TCP-based carriers. Users still
connect to Iran, and traffic still goes to your service on Kharej.

### Reverse ICMP

**When to use it.** Run `ping KHAREJ_IP` on Iran and `ping IRAN_IP` on Kharej. If Iran's ping gets 100 % loss but
Kharej's ping works, Iran's own pings are blocked one way. Some Iran IPs are greylisted like this, often one day
blocked and the next day fine. A normal ICMP tunnel cannot work then, because Iran sends the pings.

**What it changes.** Only who sends the pings. Users still connect to Iran, and traffic still goes to your service
on Kharej. Just swapping the Kharej and Iran roles would flip the port forwarding too. Reverse ICMP doesn't.

| | Sends the pings | Users connect to | Traffic goes to |
|---|---|---|---|
| Normal ICMP | Iran | Iran | Kharej `127.0.0.1:PORT` |
| **Reverse ICMP** | **Kharej** | Iran | Kharej `127.0.0.1:PORT` |

**How to turn it on.** Both servers need 2.0.0 or newer, and both must be set to reverse.

1. Update both servers (run the install command again, or `wattun` → `u`).
2. **Kharej:** `wattun` → open the tunnel → `o` (advanced settings) → `d` (direction). Enter Iran's IP when
   asked, and confirm the restart.
3. **Iran:** `wattun` → open the tunnel → `o` → `d`, and confirm the restart.
4. Run `wattun test NAME` on Kharej. It pings Iran, which is the direction this tunnel now uses.

For a new tunnel, choose reverse in the Kharej wizard's advanced settings. The token carries it, so Iran picks it up
when you paste it. In the config files it looks like this:

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

**Good to know.**

- Iran must accept pings from Kharej. Don't block incoming ICMP in Iran's firewall or cloud panel.
- Kharej sends a tiny keep-alive ping to Iran every 5 seconds. Stateful firewalls then see Iran's answers as replies
  to pings they have already seen.
- Linux on Iran also answers each tunnel ping with its own full-size reply, which doubles Iran's upload. When you
  turn reverse on for Iran, the manager rate-limits the kernel's ping replies by itself, which stops the copies.
  Normal pings to Iran keep working. (By hand: see [TECHNICAL.md](docs/TECHNICAL.md#reverse-icmp).)
- Under load, a plain `ping` from Kharej to Iran loses packets in reverse mode, because it shares the kernel's
  per-sender reply budget with the tunnel. To check the link, look at `last_rx_age_ms` in `/stats` instead.
- If both directions are blocked on a given day, no ICMP tunnel can work that day. Keep a second tunnel with
  another carrier (`wss`, `tcp`, `udp`) as a backup.

Details: [docs/TECHNICAL.md → Reverse ICMP](docs/TECHNICAL.md#reverse-icmp).

### Reverse mode for the TCP-based carriers

**When to use it.** Iran can't connect to Kharej's port (`tcp`, `tls`, `ws`, `wss`, `h2`, `h2c` or `grpc`), but Kharej
can connect to Iran. With `reverse: true` on both ends, Iran listens and Kharej dials Iran's `IP:port`. Users still
connect to Iran, and traffic still goes to your service on Kharej. Kharej needs no open port. `udp` has no reverse mode.

**How to turn it on.** In the Kharej wizard choose a TCP-based carrier, then advanced settings → reverse. It asks for
Iran's IPv4, and the carrier port you pick becomes the port Iran listens on. The token carries it, so Iran picks it up
when you paste it, and the manager opens that port in Iran's firewall. For an existing tunnel use `o` → `d`, on Kharej
first and then on Iran. Both servers need 1.8.0 or newer. Diagnose on Kharej checks that it can open
a TCP connection to Iran on that port. By hand, for `wss`:

```yaml
# Iran: /etc/wattun/iran.yml
mode: client
carrier: wss
reverse: true
listen: ":8443"
path: /wat
```

```yaml
# Kharej: /etc/wattun/kharej.yml
mode: server
carrier: wss
reverse: true
peer: 198.51.100.20:8443    # Iran's IP and the port it listens on
path: /wat
```

**Good to know.**

- The TLS options swap sides too: Iran presents the certificate (a self-signed one unless you give it `tls-cert` and
  `tls-key`), and Kharej sets `sni`, `host` and `conns`. Kharej doesn't verify the certificate unless you set
  `tls-pin`, which is fine because the pre-shared key already authenticates both ends. For strict checking, see
  [TECHNICAL.md → Reverse pool carriers](docs/TECHNICAL.md#reverse-pool-carriers).
- **It won't help if the route cuts TCP in both directions.** On one real path (measured 2026-10-10) reverse `tcp`
  stalled after 192 bytes, reverse `tls` was reset before any data, and even a plain TCP connection from Kharej to
  Iran got 3528 bytes and then stalled. Only reverse ICMP worked there. Test a plain TCP connection from Kharej to
  Iran first; if that stalls, use `icmp`.

Flags, certificates and a per-carrier table: [docs/TECHNICAL.md → Reverse mode](docs/TECHNICAL.md#reverse-mode).

## ⚙️ Configuration

Each tunnel is one readable file at `/etc/wattun/NAME.yml`, run by systemd as `wattun@NAME`. The keys are the same as
the command-line flags.

```yaml
# /etc/wattun/iran.yml
mode: client
key-file: /etc/wattun/iran.key
carrier: icmp
peer: 203.0.113.10
metrics: 127.0.0.1:19700
ports:
  - 443          # users connect to Iran :443, delivered to Kharej 127.0.0.1:443
  - 8443:443     # users connect to Iran :8443, delivered to Kharej 127.0.0.1:443
  - 53/udp
  - 5353:53/udp
```

- On Iran, `LISTEN:TARGET` publishes Iran port `LISTEN` and delivers it to port `TARGET` on Kharej (1.9.0 and
  newer). A plain `443` means `443:443`. Add `/udp` for UDP.
- Changes to `ports:` apply within 3 seconds. Any other change needs `systemctl restart wattun@NAME`.
- On Kharej, `ports:` is the allowlist of local (target) ports clients may reach. Leave it out to allow any port.
- See [docs/TECHNICAL.md](docs/TECHNICAL.md#config-file) for every key: per-port limits, FEC, pacing (`max-mbps`),
  MTU, TLS, CDN headers, and more.

## 🩺 Monitoring and troubleshooting

```bash
wattun test NAME            # run this first
systemctl status wattun@NAME
journalctl -u wattun@NAME -f
curl -s 127.0.0.1:19700/stats       # alive, last_rx_age_ms, srtt_ms, rate_bps, loss_pct, streams, sessions, bytes...
curl -s 127.0.0.1:19700/ports       # traffic per port
```

| Symptom | Likely cause and fix |
|---|---|
| `DISCONNECTED`, no errors | The key or carrier differs between the two sides. Paste the token again on Iran. For ICMP, check that `ping` works from Iran to Kharej. |
| The Iran log says `no reply from the server` or `lost contact` | The tunnel is sending but nothing comes back. Run **Diagnose** on Iran: it pings Kharej at four packet sizes and tells you which case it is (ICMP blocked, large packets dropped, wrong key or carrier, or the route blocking the answers right now). |
| Iran can't ping Kharej, but Kharej can ping Iran (often one day blocked, the next day fine) | Iran's own pings are blocked one way. Switch **both** sides to [Reverse ICMP](#-reverse-mode) (2.0.0): open the tunnel → `o` → `d`, on Kharej first (it asks for Iran's IP), then on Iran. Kharej then sends the pings and Iran answers. |
| It works some days and not others | First check the row above: if only Iran's pings are blocked, reverse ICMP fixes it. Otherwise the route between the servers is being filtered on the bad days. No tunnel can carry data while its packets are blocked. WatTunnel reconnects by itself when they pass again (keep auto-heal on). For bad days, keep a second tunnel with another carrier (`wss`, `tcp`, `udp`) as a backup. |
| ICMP: small pings work but the tunnel stalls | MTU. Keep the default 640. |
| `tcp`, `tls` or `ws` never connect | That carrier is filtered on your route, or the port is closed. Try `icmp` or `wss` behind a CDN. |
| Connected, but users can't open sites | Nothing listens on Kharej's `127.0.0.1:PORT`. The doctor checks this. |
| `address already in use` | Another program owns the port: `ss -ltnp | grep :PORT`. |
| `restart needed for KEY` in the log | Only `ports:` reloads live. Restart the tunnel. |

## 🔐 Security

- **Pre-shared key.** It's never sent over the wire. Each session derives its own key from it, and every packet is
  sealed with ChaCha20-Poly1305 under a nonce that's never reused.
- **Authenticate first.** A packet that doesn't authenticate creates no state and gets no reply, so scans and
  replays see nothing.
- **Least reach.** Kharej only forwards to `127.0.0.1`, and only to allowed ports.
- **Keys at rest.** `/etc/wattun` is `700` and key files are `600`. The **token contains the key**, so share it
  privately.
- **Scope.** WatTunnel encrypts and authenticates your traffic. It doesn't hide that a tunnel exists, or the
  servers' addresses, and it isn't an anonymity tool.

## ❓ FAQ

<details><summary><b>Do I install the same thing on both servers?</b></summary>
Yes. It's one binary. The role (Kharej server or Iran client) is chosen in the manager.
</details>

<details><summary><b>Can one Kharej serve several Iran servers?</b></summary>
Yes. Use the same token on each Iran server. Every client gets its own session and keys.
</details>

<details><summary><b>Can I run several tunnels on one server?</b></summary>
Yes. Each one has its own name, config file and systemd unit, for example one ICMP tunnel and one WSS tunnel as a
backup. The dashboard lists them all, and the manager stops two tunnels from claiming the same port.
</details>

<details><summary><b>Can users connect on a different port than my service uses?</b></summary>
Yes, from 1.9.0. In the port table, set the Iran port and the Kharej port separately (<code>8443:443</code> means
users connect to Iran 8443 and reach your service on Kharej 443).
</details>

<details><summary><b>Which server do I set up first?</b></summary>
Kharej. It creates the token that Iran needs. The manager and the installer both remind you of the order.
</details>

<details><summary><b>Does adding a port disconnect users?</b></summary>
No. Port changes are hot-reloaded. Only changing the carrier, address or key needs a restart.
</details>

<details><summary><b>What does it work with?</b></summary>
Anything on TCP or UDP: Xray, V2Ray, Sing-box, OpenVPN, WireGuard (as UDP), SSH, web panels, games.
</details>

<details><summary><b>What does Kharej need open?</b></summary>
For ICMP, it must answer ping. Don't block ICMP in the cloud firewall. With reverse ICMP it's the other way round:
Iran must answer Kharej's ping. For the other carriers, Kharej needs the listen port you chose.
</details>

<details><summary><b>Does reverse ICMP flip the port forwarding to Kharej → Iran?</b></summary>
No. Only the direction of the pings changes. Users still connect to the Iran server, and traffic still goes to your
service on Kharej. You don't need a tun device or iptables rules for it.
</details>

## 🛠 Building from source

You need Go 1.26 or newer.

```bash
git clone https://github.com/JohnWatsoon/WatTunnel && cd WatTunnel
go test ./...
sh build.sh                     # dist/wattun-linux-amd64 and -arm64, each with a .sha256
sudo bash install.sh            # installs the binary you just built
```

Layout: `wat/` holds the session, congestion control, streams and carriers. `cmd/wattun` is the binary,
`cmd/wprobe` is a path probe, and `install.sh` and `wattun-manager` are the tooling. Pushing a `v*` tag builds and
publishes a release through GitHub Actions.

Issues and pull requests are welcome. A change that makes the ICMP path slower won't be merged.

## 💬 Community and contact

- 📢 Telegram channel, for news, releases and updates: [@WatxDev](https://t.me/WatxDev)
- 👤 Developer on Telegram, for questions and feedback: [@watxox](https://t.me/watxox)

Found a bug? Open an [issue](https://github.com/JohnWatsoon/WatTunnel/issues), or send a message on Telegram.

## 📄 License

[MIT](LICENSE). Uses `golang.org/x/crypto`, `x/net` and `x/sys` (BSD-3-Clause). GOST, Backhaul and BackPack were
studied for ideas and as benchmarks. No code was copied from them.
