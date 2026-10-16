# WatTunnel

WatTunnel (`wattun`) is a tunnel. It forwards TCP and UDP ports from one server (Iran) to another (Kharej)
over a link that is filtered. It is one static Go binary, one process, and it needs no other tool.

It speaks over **ICMP echo** (the only thing the Iran filter lets through today) or over ordinary
**UDP, TCP, TLS, WebSocket, HTTP/2 and gRPC** when those work or when you hide behind a CDN.

Version: see `wat/version.go` (`wattun -version`). 

## Contents

1. [Why it exists](#why-it-exists)
2. [Install](#install)
3. [Quick start](#quick-start)
4. [Carriers](#carriers)
5. [Bonding](#bonding)
6. [Reverse mode](#reverse-mode)
   - [Auto mode](#auto-mode)
   - [CDN tuning](#cdn-tuning)
7. [UDP forwarding](#udp-forwarding)
8. [Config file](#config-file)
9. [Command-line flags](#command-line-flags)
10. [Metrics](#metrics)
11. [Handover, drain and rollback](#handover-drain-and-rollback)
12. [Troubleshooting](#troubleshooting)
13. [Security model](#security-model)
14. [Build and test](#build-and-test)
15. [License and attribution](#license-and-attribution)

## Why it exists

Since October 2026 the Iran to Kharej path cuts TCP, UDP, GRE, IPIP, SCTP and ESP after a few packets. Only ICMP echo
passes: at first only payloads up to about 640 bytes (full 1500-byte packets again since at least 2026-10-12, see
[ICMP path limits](#icmp-path-limits-and-pacing)), about 0.2 to 2 % random loss, about 40 ms. Every ready-made engine we tried
was built for another problem (a TCP stream over a clean link) and failed in a measured way on this path. WatTunnel is
built for it: small datagrams, delay-based pacing (loss is not treated as congestion), selective acks, fast loss
repair, and interactive traffic sent before bulk.

### Production numbers (real path, ICMP, 2026-10-09)

| | WatTunnel | GOST ICMP |
|---|---|---|
| Real xray vless download | about 6 MB/s | 1.6 to 5.4 MB/s |
| Real xray vless upload | about 3.7 MB/s | not measured |
| Parallel TLS requests through it | 120 of 120 ok | - |
| CPU per MB moved (Iran) | 0.05 to 0.06 CPU-s | 0.15 to 0.20 CPU-s |
| Small-request latency, idle | p50 40 to 45 ms | about 51 ms |
| RAM | about 40 MB | 50 to 70 MB |

It carries about 250 to 300 real clients. Port changes and restarts are done as live two-slot handovers: the new
instance proves itself, takes new connections, and the old one drains. Nobody is cut.

### Loopback A/B against GOST (emulated link, 2026-10-09)

Link: 20 ms each way, 0.2 % loss, 100 Mbit. Median of 2 to 3 rounds. Source:
[`bench/results-2026-10-09-final.md`](bench/results-2026-10-09-final.md).

| Contender | 1 flow MB/s | 16 x 2 MB MB/s | p50 ms | p95 ms | CPU-s/MB |
|---|---|---|---|---|---|
| direct (no tunnel) | 10.92 | 10.69 | 82 | 94 | 0 |
| wattun udp | 10.57 | 10.62 | 43 | 81 | 0.04 |
| wattun tcp | 10.55 | 10.55 | 43 | 126 | 0.03 |
| wattun tls | 10.59 | 10.25 | 43 | 108 | 0.03 |
| wattun ws | 10.59 | 10.61 | 43 | 117 | 0.03 |
| gost tcp | 10.84 | 10.41 | 83 | 95 | 0.01 |
| gost ws | 10.76 | 10.40 | 124 | 143 | 0.01 |

Read this honestly: on a clean link GOST uses less CPU and WatTunnel's pool carriers match its throughput. The
small-request latency is lower with WatTunnel because it sends interactive streams first. The ICMP numbers above are
where WatTunnel wins, because GOST cannot repair loss as fast. The h2, h2c, wss and grpc carriers are covered by unit
tests but are not in this benchmark. TCP and UDP to Kharej are blocked on the production path, so those carriers are
proven on loopback and simulated links only.

## Install

Use the installer and the `wattun` menu described in the main [README](../README.md). Running `wattun` with no
flags (or with a first argument that does not start with `-`, such as `wattun auto-test NAME`, `token NAME`, `update`,
`status` or `auto-ip NAME IP`) hands over to `/usr/local/bin/wattun-manager`, which still works by its own name.
Engine usage (flags starting with `-`) is unchanged.

**Windows (2.4.19).** Releases include `wattun-windows-amd64.exe`, the engine alone (no installer, no manager): run it
with `-config FILE` or flags, as a client or a server. Every carrier but ICMP works; `icmp` needs a Linux raw socket
and fails at start. `tcp-cc` is ignored (BBR is set only on Linux). Use Windows paths in the config file.

## Quick start

### By hand, ICMP

Pick a secret and put it in the same key file on both servers.

```bash
# Kharej (server). Needs root or CAP_NET_RAW.
echo 'my-long-secret' > /etc/wattun/key && chmod 600 /etc/wattun/key
cat > /etc/wattun/kharej.yml <<'EOF'
mode: server
key-file: /etc/wattun/key
metrics: 127.0.0.1:19700
ports:
  - 443
EOF
systemctl enable --now wattun@kharej

# Iran (client): public port 443 is forwarded to Kharej's 127.0.0.1:443
cat > /etc/wattun/iran.yml <<'EOF'
mode: client
key-file: /etc/wattun/key
peer: 203.0.113.10
ports:
  - 443
EOF
systemctl enable --now wattun@iran
```

Check: `curl -s 127.0.0.1:19700/stats` on Kharej shows `"alive": true` once Iran connects.
Do not start a second instance on a port that a live one already uses (see [Troubleshooting](#troubleshooting)).

## Carriers

All carriers carry the same encrypted session. Pick one with `carrier:` (or `-carrier`). Only ICMP needs root.

| Carrier | Use it when | Default datagram size | Needs root | Notes |
|---|---|---|---|---|
| `icmp` | Only ping passes (Iran today). | 640 bytes | yes (raw socket) | 4 lanes by default (`lanes`). Pacing is delay-based. 640 is the safe default. Raise `mtu` (up to 1400) only after checking that the path passes that size, see [ICMP path limits](#icmp-path-limits-and-pacing). |
| `udp` | UDP works and you want the lowest CPU and latency. | 1400 bytes | no | Server listens on `listen`; client dials `peer` as `host:port`. |
| `tcp` | Plain TCP works. | 4096 bytes (up to 16384) | no | A pool of connections (`conns`, default 8). Reliable underneath, the session still repairs drops. |
| `tls` | A middlebox must see HTTPS. | 4096 | no | The tcp pool inside TLS 1.3. Self-signed certificate if none is given. Pin the fingerprint with `tls-pin`. |
| `ws` | Behind a CDN or reverse proxy, port 80. | 4096 | no | WebSocket on `path`. Other requests get a plain 404. |
| `wss` | Same, with TLS (Cloudflare on 443). | 4096 | no | Set `sni` and `host` to the public name. |
| `h2` | Proxies that prefer HTTP/2. | 4096 | no | One full-duplex POST per pool connection, TLS. |
| `h2c` | HTTP/2 without TLS, behind a TLS-terminating proxy. | 4096 | no | Same as `h2`, cleartext. |
| `grpc` | CDNs that allow gRPC. | 4096 | no | Requests go to `<path>/Tun`. `plain: true` for cleartext behind a proxy. |

Rules for every non-ICMP carrier: the client dials `peer` as `host:port`, and the server listens on `listen`
(default `:4443`). `mtu` is 256 to 1400 for icmp and udp, and up to 16384 for the pool carriers.

## Bonding

`carrier: icmp+udp+tcp` joins several carriers into ONE session. The session keeps working when any one of them
is blocked, and traffic is spread over the carriers that are alive (watch `carriers` in `/stats`). Use any
combination of the carriers above, joined with `+`.

`peer` and `listen` are the defaults for every carrier in the bond. `peer-NAME` and `listen-NAME` override them for
one carrier, where NAME is the carrier name (`peer-udp`, `peer-tcp`, `listen-udp`, `listen-tcp`, ...). They are
config keys and flags like any other. ICMP takes a bare IP, the others `host:port`, so a bond usually needs the
overrides. Both ends must list the same carriers.

```yaml
# Iran (client)
mode: client
key-file: /etc/wattun/iran.key
carrier: icmp+udp+tcp
peer: 203.0.113.10          # icmp uses this (bare IP)
peer-udp: 203.0.113.10:4443
peer-tcp: 203.0.113.10:4444
ports:
  - 443
```

```yaml
# Kharej (server)
mode: server
key-file: /etc/wattun/kharej.key
carrier: icmp+udp+tcp
listen-udp: :4443
listen-tcp: :4444
ports:
  - 443
```

## Reverse mode

Normally the Kharej server listens and the Iran client dials out. Some networks only allow outbound connections from
Kharej to Iran, or only inbound to Iran. `reverse: true` swaps who listens and who dials. Nothing else changes: Iran
still opens the streams and listens on the public ports.

Works with the pool carriers (`tcp`, `tls`, `ws`, `wss`, `h2`, `h2c`, `grpc`) and, since 2.0.0, with `icmp`.
Not with `udp`. Put `reverse: true` on both ends.

| Side | Without `reverse` | With `reverse` (pool carriers) | With `reverse` (`icmp`, 2.0.0) |
|---|---|---|---|
| Iran (client) | dials `peer` | listens on `listen` | answers with ICMP replies to `peer` (Kharej's IP) |
| Kharej (server) | listens on `listen` | dials `peer` | sends ICMP requests; `peer` is Iran's IP |

Anyone who connects to the listening side can only occupy one of 64 capped slots. Their packets fail authentication
and are dropped.

### Reverse ICMP

Some Iran IPs get a one-way block: Iran's own pings to Kharej are dropped (`ping KHAREJ` from Iran shows 100 % loss),
but `ping IRAN` from Kharej works. The block often comes and goes from day to day. Normal ICMP mode cannot work then,
because the Iran client sends the requests. With `reverse: true` on both ends the ICMP direction is swapped: Kharej
sends the requests (`echo` type 8, or the request type of `icmp-type`) and Iran answers with replies. Which side opens
the streams and which ports are published do not change.

- Both ends need wattun 2.0.0 or newer with `reverse: true`. A 1.9 peer, or one end without `reverse`, never
  connects: the two ends then listen for the same ICMP type.
- On Kharej, set `peer` to Iran's IP. Kharej sends one empty request per lane every 5 s to it (the knock), so a
  stateful firewall on either end, or on the route, sees Iran's replies as answers to requests it has seen. Without
  `peer` Kharej still answers whatever address authenticates, but nothing is knocked.
- Iran keeps `peer` = Kharej's IP, the address its replies go to.
- Iran must receive pings from Kharej: do not block incoming ICMP there.
- **Kernel copies on Iran.** Linux on Iran also answers every tunnel request with its own full-size reply, so Iran
  uploads everything twice. Measured on the real path: `OutEchoReps` = 2 x `InEchos` in `/proc/net/snmp`. Kharej
  drops the copies (they fail authentication), and since 2.0.1 they no longer count as activity from Iran (before
  that, a dead Iran client's session never went idle on Kharej). To stop the copies, rate-limit the kernel's own
  replies on Iran:

  ```
  # /etc/sysctl.d/90-wattun-reverse.conf
  net.ipv4.icmp_ratemask = 22553   # default 6168 + bit 0 (echo reply) + bit 14 (timestamp reply)
  net.ipv4.icmp_ratelimit = 100    # kernel replies: 10 per second per sender (default 1000 ms)
  ```

  wattun's replies are raw-socket sends and are not limited. Ordinary pings to Iran are still answered. Measured
  after the change: 15.9 – 18.2 MB/s each way. Since 2.1.1 the manager applies this by itself, without a question, when reverse is turned on for an Iran
  tunnel and restores the old values when the last one is gone. `icmp_ratelimit` applies to every type in the
  mask, so destination-unreachable and time-exceeded messages also go from 1 to 10 per second per destination.
  `net.ipv4.icmp_echo_ignore_all=1` also works (the tunnel still receives its packets), but then Iran answers no
  ping at all, which breaks monitoring that pings it.
- **Don't judge Iran by ping from Kharej under load.** The kernel limit is per sender, and in reverse mode every
  tunnel request comes from Kharej's IP, so a plain `ping` from Kharej competes with the tunnel for that budget and
  loses packets while traffic flows (measured 4/6 and 1/3 received during a speed test). Use `last_rx_age_ms` from
  `/stats` instead (see Metrics).
- In `wattun`: Kharej setup → advanced settings → reverse, or for an existing tunnel Advanced settings →
  `d` on both sides. The token carries the flag (field 8), so a fresh Iran setup picks it up.

### Reverse pool carriers

For `tcp`, `tls`, `ws`, `wss`, `h2`, `h2c` and `grpc`. Use it when Iran cannot reach a port on Kharej but Kharej can
open connections to Iran. Iran listens on `listen`, Kharej dials Iran's `IP:port` as `peer`. The session roles do not
change: users still connect to Iran, and traffic still goes to Kharej's `127.0.0.1:PORT`. Put `reverse: true` and the
same `key`, `carrier` and `path` on both ends. Needs a port that Iran's firewall allows in; Kharej needs no open port.

The TLS and HTTP flags swap sides along with the roles:

| Key | Set on | Used for |
|---|---|---|
| `listen` | Iran (listener) | Address to accept Kharej on, e.g. `:8443`. |
| `peer` | Kharej (dialer) | Iran's `IP:port`, the same port as Iran's `listen`. |
| `tls-cert`, `tls-key` | Iran (listener) | Certificate to present. Empty = an in-memory self-signed certificate generated at start. |
| `sni`, `host`, `header` | Kharej (dialer) | TLS server name, Host/authority and extra headers of the outgoing connections. |
| `tls-pin` | Kharej (dialer) | Hex sha256 of Iran's certificate. |
| `conns` | Kharej (dialer) | Number of connections dialed to Iran. |
| `plain` | both | grpc without TLS. |
| `path` | both | URL path. Must match. |

**Certificates.** Without `tls-pin` the dialer (Kharej) does not verify Iran's certificate. This is intended: the
pre-shared key (the ChaCha20-Poly1305 session) already stops an impostor, and TLS only shapes the traffic. For strict
checking, give Iran a real certificate (`tls-cert`, `tls-key`) and set `tls-pin` on Kharej to its sha256 fingerprint
(hex).

Example, `wss`:

```yaml
# Iran: listens, still opens the streams and serves the public ports
mode: client
key-file: /etc/wattun/key
carrier: wss
reverse: true
listen: ":8443"
path: /wat
ports:
  - 443
```

```yaml
# Kharej: dials out to Iran
mode: server
key-file: /etc/wattun/key
carrier: wss
reverse: true
peer: 198.51.100.20:8443
path: /wat
sni: example.com      # optional
conns: 8
ports:
  - 443
```

In `wattun`:

- New tunnel: Kharej setup → advanced settings → reverse. It asks for Iran's IPv4, and the carrier port P you chose
  becomes the port Iran listens on. The token carries the flag, so Iran picks it up when you paste it.
- Existing tunnel: open it → `o` (advanced settings) → `d` (direction), on Kharej first, then on Iran.
- On Iran the manager opens P/tcp in the firewall. Kharej needs no open port.
- Diagnose: on Kharej it tests a TCP connection Kharej → Iran on P. On Iran it checks that P is listening.

**When it does not help.** Reverse only changes who dials. If the route cuts TCP in both directions, it does not
matter who opens the connection. Field result on one real Iran-Kharej path (measured 2026-10-10): reverse `tcp`
stalled after 192 B, reverse `tls` was reset before any data, and a plain TCP socket from Kharej to Iran connected,
received 3528 B and then stalled (3 out of 3 tries). That filter cuts TCP both ways, and only reverse ICMP worked
there. If a plain TCP connection from Kharej to Iran's port already stalls, use reverse `icmp` or the normal `icmp`
instead.

Since 2.1.0 the reverse dialers back off up to 30 s between attempts. They log the first failure, then at most one
failure line every 5 minutes, and a `connected` line when a dial succeeds.

### Carrier matrix

| Carrier | Direct | Reverse | Minimum version (both ends) |
|---|---|---|---|
| `icmp` | yes | yes | direct: any; reverse: 2.0.0 |
| `udp` | yes | no | not applicable (no reverse) |
| `tcp`, `tls`, `ws`, `wss`, `h2`, `h2c`, `grpc` | yes | yes | direct: 1.3.0; reverse: 1.8.0 |

The reverse pool carriers are in the first release of this repository's history (1.8.0). An earlier release may
have had them too; this table says 1.8.0 because that is the oldest one that can be checked.

## Auto mode

The manager only (`wattun`, no engine flag). It needs `wattun` 2.1.0 on Kharej and `systemd-run`. It finds the carrier that
works on a route by testing all of them, so the operator does not have to guess.

**Kharej.** In the new-tunnel wizard the first carrier option is `auto`. It asks for an optional Cloudflare-proxied
domain, used only to test the CDN carriers through Cloudflare. It creates one bonded server tunnel `NAME` that listens
on every carrier, and prints one token.

| Carrier | Listen port |
|---|---|
| `udp`, `tcp` | 4443 |
| `tls` | 8443 |
| `ws` | 2052 |
| `wss` | 2053 |
| `h2` | 2087 |
| `h2c` | 2082 |
| `grpc` | 2083 |
| `icmp` | none |

A port that is already taken moves to a free fallback; the real ports are in the token.

**Token.** `wat1:` + base64 of `carrier|peer|key|path|sni|icmp-type|allowed-ports|reverse|plan`. Field 9 (`plan`) looks
like `d=udp:4443,tcp:4443,...;r=tcp:24431,tls:24432,ws:24433,wss:24434,h2:24435,h2c:24436,grpc:24437`. `d` is the
Kharej listen port per carrier. `r` is the port Iran listens on for each reverse test. Tokens with 7 or 8 fields (older
managers, non-auto tunnels) still work.

**Reverse side.** A transient unit `wattun-autowatch-NAME` (`systemd-run`, 1 hour at most) polls the Kharej tunnel's
`/stats` `clients` list. When Iran's first test client connects, it learns Iran's IP and writes and starts a companion
tunnel `NAME-r`: a reverse server with reverse ICMP and reverse dials to Iran's `r` ports. With a CDN domain set, the IP
is taken only from `icmp`, `udp`, `tcp` and `tls` clients, because CDN clients show the proxy's IP. Manual fallback on
Kharej: `wattun auto-ip NAME IRAN_IP`. `NAME-r` appears on the dashboard as the reverse side of `NAME`, follows
its ports and key, and is deleted with it.

**Iran test.** Pasting an auto token runs the test (re-run later with `wattun auto-test NAME`). Phases: direct,
then CDN (if a domain was given), then reverse. Each variant is a throw-away client with its own `/speedtest`
(2 MB down + up). Since 2.1.1 the reverse variants are started all at once and get up to 45 s to connect (Kharej's
reverse dialer backoff made most of them fail with "no link in 8 s" before). Nothing is published; temp files are in `/run/wattun-auto`. Reverse test ports are opened in the
firewall only during their probe. Since 2.1.1 the manager opens ufw/firewalld ports without a confirm, Kharej does not
ask which ports Iran may reach (all are allowed; restrict later in the port editor), and Iran enables auto-heal by
itself (off: `wattun` → `s` → `h`). The table is ranked by download plus upload (ties: lower RTT) and accepts Enter (best), `b` (bond the working carriers), `1`-`N`
(one variant) and `q`. The normal wizard continues at port mapping. The token is saved in `/etc/wattun/NAME.auto`.

**Auto-heal.** After two failed restart cycles on an auto tunnel, `wattun-manager heal` starts a re-test (1 MB, at most
once per 30 minutes). It switches to another working variant only when the current one fails, and logs
`wattun-heal: switched NAME from X to Y`.

**Costs and limits.** Several ports are open on Kharej at once. The test takes about 2 to 3 minutes. Kharej must be
2.1.0 or newer (the `clients` field and the reverse dial backoff). The wire format did not change, so 2.1.0 peers work
with 2.0.x ones for normal tunnels.

## CDN tuning

Since 2.2.0, client (Iran) side only. Kharej and the wire format are unchanged, so any 2.x Kharej works.

**Why.** Field findings from a real Iran server (October 2026): the filter lets the TLS handshake through and then
black-holes the flow by the SNI of the user's own domain. The edges DNS returns for the Cloudflare zone were
degraded while other edges (for example 162.159.140.220) worked. Domain fronting (another SNI, your Host) gets a 403
from Cloudflare. Plain `ws` on HTTP ports through Cloudflare hung at the Upgrade. So the tuning picks edges and
TLS behaviour, and does not rely on fronting.

**Client keys.**

- `peer: A,B,C` accepts several comma-separated addresses for the pool carriers. Slots spread over them, and a dead
  address fails over at once. `/stats` shows them in `edges`.
- `fp` sets the ClientHello fingerprint (utls). `ech: auto` hides the domain with Encrypted Client Hello and falls
  back to no ECH if the record is missing. `tls-frag: N` splits the ClientHello.
- ALPN: `ws` and `wss` force `http/1.1`; `h2` and `grpc` require `h2`.

**What the manager does.** When Iran sets up a CDN tunnel (`wss`, `h2`, `grpc`, `ws`, `h2c` through a Cloudflare
domain) it runs, without questions:

1. Scan about 22 Cloudflare edge IPs, with the domain's own A records first. One test client dials all the candidate
   edges with a real ECH connection to the domain, and an edge counts only if that connection works. This replaces the
   old curl probe and the `speed.cloudflare.com` ranking, because an edge serving `speed.cloudflare.com` can still fail
   for the zone. IPv6 edges are tried only when the server has an IPv6 route.
2. Keep the best 3 as `peer`.
3. Speed-test, in this order: Chrome fingerprint with ECH first (the test stops early when it works), then the other
   variants (plain, fragmentation) only if it does not. Through Cloudflare only `wss` and `grpc` are tested.
4. Write the winner (`fp`, `ech`, `tls-frag`, `peer`) into the config and restart.

In Auto mode this is part of the CDN phase; the table labels look like `wss · chrome · 3 edges`.
`wattun cdn-tune NAME [full]` repeats the tuning at any time. Auto-heal refreshes dead edges.

**DoH behaviour (2.2.1).** `ech: auto` looks up the domain's HTTPS record by racing all four DoH servers (1.1.1.1,
1.0.0.1, 8.8.8.8, 9.9.9.9) and takes the first answer; from Iran 1.1.1.1 was blocked while 8.8.8.8 worked. The lookup
happens before the dial. If DoH fails, the last good config is kept, and after a rejection the config is refreshed in
the background.

**Field result (v2.2.0, real Iran server through Cloudflare).** Only ECH got through; every non-ECH variant failed.
With ECH: `wss` 8.0 MB/s down and 7.5 MB/s up, `grpc` 6.7 MB/s down and 9.9 MB/s up.

**Cloudflare settings.** Use `wss` or `grpc` on a Cloudflare HTTPS port (443, 2053, 2083, 2087, 2096, 8443),
SSL mode Full, ECH on, and enable gRPC in the Cloudflare Network settings for `grpc`. `h2` does not work through
Cloudflare: it speaks HTTP/1.1 to the origin except for gRPC. Avoid plain `ws` on HTTP ports.

**Troubleshooting.**

| Symptom | Cause and fix |
|---|---|
| Connects, then stalls with no data | SNI black-holing. Set `ech: auto`, or try `fp: chrome` and `tls-frag`. Run `wattun cdn-tune NAME full`. |
| All edges fail the scan | The domain is blocked even over ECH, or the zone has no ECH. Check `ech` and `tls_mode` in `/stats` and that the domain's HTTPS record exists. |
| `ech: false` although `ech: auto` is set | The domain has no HTTPS DNS record (the zone is not on Cloudflare's ECH), or all four DoH servers are blocked and no earlier config was cached. The tunnel runs without ECH. |
| `h2` never works through Cloudflare | Expected: Cloudflare speaks HTTP/1.1 to the origin except for gRPC. Use `wss` or `grpc`. |
| `grpc` never connects | gRPC is off in Cloudflare Network settings. |
| `ws` hangs at the Upgrade | Plain ws on an HTTP port. Move to `wss` on an HTTPS port. |
| 403 from Cloudflare | A fronted SNI/Host mismatch. Keep `sni` and `host` the same domain. |
| One entry in `edges` has `up: false` | That edge is dead. Auto-heal replaces it, or run `wattun cdn-tune NAME`. |
| Works from some Iran servers or networks, fails on others | `peer` is the Kharej server's own IP, so the tunnel never goes through Cloudflare. It works only where that IP is reachable. Proxy a domain to Kharej (orange cloud), enter the domain as the Kharej address, or run `wattun cdn-tune NAME` to write Cloudflare edges into `peer`. Also check that `sni`/`host` is spelled exactly like the domain. |

**Direct-IP warning (manager).** The `wss`, `grpc` and `h2` carriers dial `peer` and send `sni` as the TLS name, so
with `peer` set to the origin's IP the connection goes straight to Kharej, not through Cloudflare, even when `sni`
is the domain. When an Iran tunnel on one of those carriers is created with a bare IPv4 `peer` (not reverse, not set
up through CDN tuning), the manager warns before creating it and suggests the domain or `cdn-tune`.

## UDP forwarding

Since 1.2.0 WatTunnel also forwards UDP ports (WireGuard, DNS, QUIC, game servers) as unreliable datagrams inside the
same session. Datagrams are not retransmitted and are dropped when a queue is full. That is correct for UDP.

- Config: add `N/udp` to the `ports:` list on both ends. A plain `N` (or `N/tcp`) is TCP.
- Flag: `-udp PORT` or `-udp listenPort:serverPort[@bind][,...]` on the client.
- The server only forwards to UDP ports that are listed as `/udp`. A TCP-only list allows no UDP.
- Idle flows are closed after `udp-idle` (default 60 s).
- Both ends need wattun 1.2.0 or newer.
- Big datagrams (2.4.19): a datagram larger than one tunnel packet (about 1350 bytes on udp, 590 on the default
  icmp) is sent in up to 64 pieces and rebuilt on the other end, so WireGuard's default MTU 1420 works. Both ends
  need 2.4.19; with an older end such datagrams are dropped (`dgram_dropped_size`): set `MTU = 1280` in WireGuard on
  udp or icmp `mtu: 1400`, or about 550 on the default icmp. Losing one piece loses the datagram, so on a lossy path
  a smaller WireGuard MTU still does better.

```yaml
ports:
  - 443          # tcp
  - 51820/udp    # udp
```

## Config file

`-config /etc/wattun/NAME.yml` supplies flags. It is a small YAML subset:

- `key: value` per line. The keys are the flag names.
- `#` starts a comment. Values may be in "double" or 'single' quotes.
- One list, `ports:`, with `- PORT`, `- PORT/udp`, `- LISTEN:TARGET` or `- LISTEN:TARGET/udp` items.
- Unknown keys, duplicate keys and bad values stop the start with a line number. Only `header` may repeat.
- Command-line flags win over the file.
- The `ports:` list is **hot-reloaded** every 3 seconds. On the client it opens and closes listeners. On the server it
  replaces the allowlist. A file that fails to parse is ignored and the old state stays. Changing any other key logs
  `restart needed for KEY`.
- With a `ports:` key on the server, the file replaces `allow-ports` and `allow-file`.

On the client, a plain `N` in `ports:` means: listen on `bind:(N + port-offset)` and forward to server port N. Since
1.9.0 an item `LISTEN:TARGET` listens on `LISTEN` and forwards to server port `TARGET`. Both are 1-65535 and may be
followed by `/tcp` or `/udp`. A listen port may appear only once per protocol. Changing only the target of a listen port
in the file closes and reopens that listener (connections already open keep running).

```yaml
# Iran (client)
ports:
  - 443         # listen 443 -> server 443
  - 8443:443    # listen 8443 -> server 443
  - 5353:53/udp # listen udp 5353 -> server udp 53
```

The server allowlist is the **target** ports, so Kharej's list contains `443` and `53/udp` for the example above (not
`8443` or `5353`). `-map` and `-udp listenPort:serverPort` on the command line behave as before.

### Keys

| Key | Default | Side | Meaning |
|---|---|---|---|
| `mode` | (required) | both | `client` or `server`. |
| `key` | | both | Pre-shared key. Prefer `key-file`. |
| `key-file` | | both | File with the key (whitespace trimmed). Same on both ends. |
| `carrier` | `icmp` | both | One of the carriers above, or several joined with `+` (see Bonding). |
| `peer-NAME`, `listen-NAME` | = `peer`, `listen` | client / server | Bonded carriers only: per-carrier address (`peer-udp`, `listen-tcp`, ...). |
| `peer` | | client (server with `reverse`) | icmp, udp: server IP. Others: `host:port`. Reverse pool carriers: Kharej sets Iran's `IP:port`. Reverse icmp: Kharej sets Iran's IP, Iran keeps Kharej's. |
| `listen` | `:4443` | server (client with `reverse`) | Address for non-ICMP carriers. With `reverse` Iran listens here and Kharej's `peer` must point to it. |
| `reverse` | false | both | Swap who listens and who dials. With `icmp` (2.0.0): Kharej sends the requests, Iran replies. |
| `ports` | | both | List of `N`, `N/udp`, `LISTEN:TARGET` and `LISTEN:TARGET/udp`. Client listens on LISTEN, server allows TARGET. Hot-reloaded. |
| `bind` | `0.0.0.0` | client | Address of the public listeners. |
| `port-offset` | 0 | client | Added to every listen port. Used by the second slot of a handover. |
| `lanes` | 4 | client | ICMP identifiers to stripe over. |
| `conns` | 8 | client (server with `reverse`) | Connections in a pool carrier. With `reverse`, Kharej dials this many to Iran. |
| `mtu` | 0 (carrier default) | both | Datagram size cap, including header and tag. |
| `max-mbps` | 0 (carrier default) | both | Pacing ceiling, MB/s per direction, per session. 0 = 16 when `icmp` is among the carriers, 1250 (10 Gbit, i.e. no practical cap) for udp, tcp, tls, ws, wss, h2, h2c and grpc since 2.4.18 (200 from 2.3.0; before that 16 for every carrier; the server's value caps the download). See "ICMP path limits and pacing". |
| `tcp-cc` | `bbr` | both | Since 2.4.18, Linux. TCP congestion control set on every pool socket (tcp, tls, ws, wss, h2, h2c, grpc). BBR does not back off on random loss; the kernel default (cubic) halves its window on every lost segment. `system` keeps the kernel default. Each end sets it for what it sends. `tcp_cc` in `/stats` shows what the kernel accepted (falls back to the default if the `tcp_bbr` module is missing). |
| `sessions` | 1 | client | Independent sessions to the server, 1 to 16 (2.3.0, client only; the server is unchanged). See "Several sessions". |
| `icmp-type` | `echo` | both | ICMP carrier: `echo`, `timestamp`, `info` or `mask`. Both ends must match. |
| `loss-ceiling` | false | both | Opt-in loss-aware ceiling for the pacer (see "ICMP path limits and pacing"). Off = delay only. |
| `slack-ms` | 8 | both | RTT growth tolerated before slowing down. |
| `hedge` | false | both | Send small young packets twice. Helps lossy tails, costs packets. |
| `fec` | off | both | `off` or `auto`: adaptive XOR parity for small transfers (see FEC). Needs 1.7.0 and `auto` on both ends. |
| `allow-min`, `allow-max` | 1, 65535 | server | Range of target ports clients may ask for. |
| `allow-ports` | | server | Comma list of allowed target ports. |
| `allow-file` | | server | File with allowed ports, re-read when it changes. Overrides `allow-ports`. |
| `udp` | | client | UDP forwards, `PORT` or `listenPort:serverPort[@bind]`. |
| `udp-idle` | 60s | both | Close UDP flows idle this long. |
| `tls-cert`, `tls-key` | in-memory self-signed | server (client with `reverse`) | Certificate files for tls, wss, h2 and grpc, on whichever side listens. |
| `sni` | | client (server with `reverse`) | Server name in the TLS ClientHello, set on whichever side dials. |
| `tls-pin` | | client (server with `reverse`) | Hex sha256 of the listener's certificate. Also makes the dialing side check it. Without it the dialer does not verify the certificate. |
| `path` | `/wat` | both | URL path for ws, wss, h2, h2c, grpc (grpc: service name). Same on both ends, also with `reverse`. |
| `host` | = `peer` | client (server with `reverse`) | Host header / authority, set on whichever side dials. |
| `plain` | false | both (dialer with `reverse`) | grpc without TLS. |
| `header` | | client (server with `reverse`) | Extra request header `Name: value`. Repeatable. |
| `fp` | `go` | client (server with `reverse`) | TLS ClientHello fingerprint (utls): `go`, `chrome`, `firefox`, `safari`, `edge` or `random`. Since 2.2.0. |
| `ech` | `off` | client (server with `reverse`) | Encrypted Client Hello, hides the SNI: `off`, `auto` or a base64 ECHConfigList. `auto` fetches the domain's HTTPS DNS record over DoH, by IP (1.1.1.1, 1.0.0.1, 8.8.8.8, 9.9.9.9), and falls back to no ECH. Since 2.2.0. |
| `ech-cache` | empty (off) | client, with `ech: auto` | File that keeps the last good ECHConfigList (`name base64` per line, written atomically, 0600). On start it is used at once while DoH refreshes in the background; cache errors are logged once and never stop the tunnel. Since 2.2.3. |
| `tls-frag` | 0 | client (server with `reverse`) | Split the ClientHello into pieces of N bytes. 0 = off. Since 2.2.0. |
| `metrics` | off | both | Serve `/stats` and pprof on this address. Always loopback (see Metrics). |
| `debug` | false | both | Log every stream open and close. |

### Example: ICMP (the production setup)

```yaml
# /etc/wattun/iran.yml   (Kharej: mode: server, no peer/bind/lanes)
mode: client
key-file: /etc/wattun/key
peer: 203.0.113.10
lanes: 4
max-mbps: 16
metrics: 127.0.0.1:19702
ports:
  - 443
  - 2053
  - 51820/udp
```

### Example: TCP pool

```yaml
# Iran: /etc/wattun/iran.yml
mode: client
key-file: /etc/wattun/key
carrier: tcp
peer: 203.0.113.10:4443
conns: 8
ports:
  - 443
```

```yaml
# Kharej: /etc/wattun/kharej.yml
mode: server
key-file: /etc/wattun/key
carrier: tcp
listen: ":4443"
ports:
  - 443
```

### Example: WebSocket behind Cloudflare

Cloudflare terminates TLS and forwards to Kharej over plain WebSocket on a port it supports (for example 8080).

```yaml
# Iran
mode: client
key-file: /etc/wattun/key
carrier: wss
peer: tunnel.example.com:443
sni: tunnel.example.com
host: tunnel.example.com
path: /api/v2/stream
conns: 8
ports:
  - 443
```

```yaml
# Kharej (origin behind Cloudflare, orange cloud on)
mode: server
key-file: /etc/wattun/key
carrier: ws
listen: ":8080"
path: /api/v2/stream
ports:
  - 443
```

Use a path that looks like a normal API route. Any other path gets a plain 404.

### Example: reverse

Kharej cannot be reached from Iran, but can reach Iran.

```yaml
# Iran: listens, still opens the streams and serves the public ports
mode: client
key-file: /etc/wattun/key
carrier: tcp
reverse: true
listen: ":4443"
ports:
  - 443
```

```yaml
# Kharej: dials out to Iran
mode: server
key-file: /etc/wattun/key
carrier: tcp
reverse: true
peer: 198.51.100.20:4443
ports:
  - 443
```

## Command-line flags

Every flag can also be a config key. Flags win over the file.

| Flag | Default | Meaning |
|---|---|---|
| `-mode client\|server` | | Role. |
| `-key SECRET`, `-key-file FILE` | | Pre-shared key. |
| `-config FILE` | | Config file (above). |
| `-carrier NAME` | `icmp` | Transport, or `a+b+c` to bond several. |
| `-peer-NAME ADDR`, `-listen-NAME ADDR` | | Bonded carriers: per-carrier peer / listen address. |
| `-peer ADDR` | | Server IP (icmp, udp) or `host:port`. |
| `-listen ADDR` | `:4443` | Listen address of non-ICMP carriers. |
| `-reverse` | off | Swap dial and listen (pool carriers), or which side sends the ICMP requests (`icmp`, 2.0.0). |
| `-map l:s[,...]` | | Client: listen port to server port. `l:s@127.0.0.1` keeps a port private. |
| `-udp SPEC` | | Client: UDP forwards. |
| `-udp-idle D` | `60s` | UDP flow idle timeout. |
| `-bind ADDR` | `0.0.0.0` | Client listen address. |
| `-port-offset N` | 0 | Added to every client listen port. |
| `-lanes N` | 4 | ICMP identifiers. |
| `-conns N` | 8 | Pool connections. |
| `-mtu N` | 0 | Datagram cap. |
| `-max-mbps F` | 0 | Pace ceiling per direction and session; 0 = 16 with icmp, 1250 otherwise (2.4.18; 200 from 2.3.0). |
| `-tcp-cc NAME` | `bbr` | Pool sockets' TCP congestion control, Linux (2.4.18). `system` keeps the kernel default. |
| `-sessions N` | 1 | Client: N independent sessions, udp and the pool carriers only (2.3.0, server unchanged). |
| `-icmp-type T` | `echo` | ICMP carrier: `echo`, `timestamp`, `info`, `mask` (both ends the same). |
| `-loss-ceiling` | off | Pacer: also cut the rate when loss jumps far above its learned baseline (opt-in). |
| `-slack-ms N` | 8 | Tolerated RTT growth. |
| `-hedge` | off | Duplicate small young packets. |
| `-fec auto` | off | Adaptive FEC, both ends (see FEC). |
| `-allow-min`, `-allow-max` | 1, 65535 | Server: target port range. |
| `-allow-ports LIST` | | Server: allowed target ports. |
| `-allow-file FILE` | | Server: allowed ports file, hot-reloaded. |
| `-tls-cert`, `-tls-key` | | Server: certificate files. |
| `-sni`, `-tls-pin` | | Client: TLS name, certificate fingerprint. |
| `-path`, `-host`, `-header`, `-plain` | `/wat` | HTTP carrier options. |
| `-fp NAME` | `go` | Dialer: TLS fingerprint `go`, `chrome`, `firefox`, `safari`, `edge`, `random` (2.2.0). |
| `-ech MODE` | `off` | Dialer: `off`, `auto` or a base64 ECHConfigList (2.2.0). |
| `-ech-cache FILE` | empty | Dialer, with `-ech auto`: ECH config cache file (2.2.3). |
| `-tls-frag N` | 0 | Dialer: split the ClientHello into N-byte pieces (2.2.0). |
| `-metrics ADDR` | off | Serve `/stats` and pprof. |
| `-debug` | off | Log every stream. |
| `-version` | | Print `wattun X.Y.Z` and exit. |

Signals: `SIGTERM` or `SIGINT` stops. On a server, `SIGUSR1` starts a drain (below).

## FEC

`fec: auto` (flag `-fec auto`, default `off`) cuts the tail latency of small request/response traffic on a lossy
path. After a burst of small packets, or every k of them, the sender emits one XOR parity packet over their
plaintext; if exactly one of them was lost the receiver rebuilds it, processes and acks it, so the sender does not
wait for a PTO (about 1.25 RTT) or for later acks. k adapts from 4 to 16 with the observed loss (more loss, smaller
k). Full-size packets are never covered and nothing is sent while the session is cwnd-limited, so bulk transfers pay
under 5 % extra packets. Both ends must run 1.7.0 with `fec: auto` for it to help: a peer with FEC off ignores the
parity packet, and an older peer stops parsing at the unknown frame, which sits alone in its packet. Counters:
`fec_sent`, `fec_recovered`.

## Per-port traffic and limits

Both ends count traffic per port (client: the public port users connect to; server: the target port) and expose it
live in `/stats` under `ports` and on a cheap `/ports` endpoint (needs `-metrics`). Counters are cumulative since
process start. Since 2.4.19 the `*_total` and `conns_all_time` fields also keep counting across restarts: they are
saved to `<config>.totals.json` every 30 s and on shutdown (with `-config` only). Delete that file to start them from
zero.

```json
{"20001": {"bytes_up": 0, "bytes_down": 0, "bytes_up_total": 0, "bytes_down_total": 0,
  "conns_total": 0, "conns_all_time": 0, "conns_active": 0, "udp_flows_active": 0,
  "dgram_up": 0, "dgram_down": 0, "errors": 0, "refused": 0,
  "rate_bps_up": 0, "rate_bps_down": 0, "peak_bps_up": 0, "peak_bps_down": 0,
  "rate_limit_bps": 0, "quota_limit": 0, "quota_used": 0, "quota_exceeded": false}}
```

`up` is client to server payload. Rates are bytes/s over the last 1 s, peaks the best 1 s window. A UDP flow counts as
a connection. `refused` counts connections or datagrams turned away by a quota or rate limit.

Limits go in the config file (hot-reloaded every 3 s, like `ports:`), one item per port, sizes in decimal units
(`300k`, `5MB`, `1.5GB`):

```yaml
limits:
  - 20001 rate=5MB quota=100GB
  - 20002 rate=500k
```

- `rate`: bytes/s, applied to each direction separately and shared by all connections of the port (TCP is paced, UDP
  datagrams over the rate are dropped). No limit set means zero overhead.
- `quota`: total up+down bytes. Once used up, new connections are closed at once and existing ones are cut. Usage is
  saved to `<config>.quota.json` every 30 s and on shutdown, so a restart does not reset it. Removing the `quota=`
  item lifts the cut-off.
- Put limits in the file of the side that should enforce them (normally the client in Iran).
- Reset: `curl -X POST 'http://127.0.0.1:19700/quota/reset?port=20001'` (loopback callers only).

## Metrics

With `metrics: 127.0.0.1:PORT`, `GET /stats` returns JSON. `/debug/pprof/` is on the same address. Keep it on
localhost.

Since 2.0.2 the metrics address is always loopback: a non-loopback value (`0.0.0.0:19700`, a public IP, a bare
`:19700`) is rewritten to `127.0.0.1` with the same port, and a log line says so, because `/stats`, pprof and
`/speedtest` must never be reachable from outside. The server also never forwards a tunnel stream to its own
metrics port, even if the port is in the allowlist.

| Field | Meaning |
|---|---|
| `version` | The wattun version string (for example `2.0.2`). |
| `carriers` | Only with bonded carriers (`carrier: a+b`): one entry per carrier with `name`, `alive`, `srtt_ms`, `share` (fraction of traffic), `sent`, `acked`, `lost`. |
| `ports` | Per-port counters (same data as `/ports`). |
| `alive` | Server: at least one client session (a session closes 45 s after its last packet). Client: an authenticated packet from the server arrived in the last 10 s (each side pings at least every 2 s, so an idle link stays alive); with `sessions` > 1, on any session. |
| `last_rx_age_ms` | Since 2.0.1. Milliseconds since the last authenticated packet from the peer (server: from any client, including sessions that have closed). `-1` = none since the process started. Monitors should use this rather than ping: it only moves on real tunnel packets. |
| `clients` | Since 2.1.0, servers only. One entry per live client session: `[{"ip":"203.0.113.5","carrier":"tcp","age_ms":1234}]`. Behind a CDN carrier (`ws`, `wss`, `h2`, `h2c`, `grpc`) `ip` is the proxy's address. Auto mode uses it to learn Iran's IP. |
| `tls_fp` | Since 2.2.0, pool carriers. The TLS fingerprint in use (`go`, `chrome`, ...). |
| `tls_mode` | Since 2.2.0. Fingerprint plus ECH state, for example `chrome+ech`, `go`. |
| `ech` | Since 2.2.0. `true` when Encrypted Client Hello is active on the dialed connections. |
| `edges` | Since 2.2.0, when `peer` lists several addresses: `[{"addr":"162.159.140.220:443","up":true}]`, one entry per address. |
| `sessions` | Server: client sessions. Client: the configured `-sessions` (1 before 2.3.0). |
| `sessions_up` | Since 2.3.0, clients. Sessions that are alive. |
| `session_list` | Since 2.3.0, clients with `sessions` > 1: one entry per session, `[{"alive":true,"srtt_ms":41.2,"rate_bps":2.4e7,"streams":3}]`. |
| `draining` | Server: not accepting new sessions. |
| `streams` | Open TCP streams. The drain timer waits for 0. |
| `srtt_ms`, `min_rtt_ms` | Smoothed and minimum round-trip time. |
| `rate_bps` | Current send rate in bytes per second. |
| `ceiling_bps` | Loss-aware soft ceiling in bytes per second (0 = none active). |
| `loss_pct` | Loss in the last judged 50 ms interval, percent (0 until 50 packets were sent in one). |
| `inflight` | Unacknowledged bytes. |
| `pkts_out`, `pkts_in`, `bytes_out`, `bytes_in` | Totals since the process started. |
| `bytes_out_total`, `bytes_in_total` | Since 2.4.19. Wire bytes across restarts (saved in `<config>.totals.json`); the manager shows these. |
| `dgram_fragmented`, `dgram_reassembled` | Since 2.4.19. UDP datagrams too big for one packet that were sent in pieces / rebuilt from pieces (needs 2.4.19 on both ends; an older peer drops the pieces). |
| `retrans` | Retransmitted packets. |
| `fec_sent`, `fec_recovered` | FEC parity packets sent; packets rebuilt from parity. |
| `send_errors` | Carrier send failures. |
| `ack_late` | Since 2.4.18, reliable carriers. Received packets that only a late ACK reported (they arrived below the newest 64 ranges, see [Direct pools (2.4.18)](#direct-pools-2418)). |
| `dup_recv`, `rx_too_old` | Since 2.4.18. Packets dropped on receive as already seen, and as older than the replay window (131072 packets on reliable carriers). `rx_too_old` above 0 means data was lost and resent. |
| `dgram_sent`, `dgram_recv` | UDP datagrams. |
| `dgram_dropped_queue`, `dgram_dropped_size`, `dgram_dropped_rx` | UDP drops: queue full, too big, bad on receive. |
| `dgram_flows` | Active UDP flows. |
| `dgram_rejected` | UDP flows refused (port not allowed). |
| `dgram_flow_cap_drops` | Datagrams dropped at the flow cap. |
| `tcp_cc` | Since 2.4.18. The congestion control the kernel set on pool sockets. |
| `pool_drops` | Since 2.4.18. Packets dropped because a pool connection's queue was full (should stay 0; the session waits instead). |
| `pool_conn_deaths` | Since 2.4.18. Pool connections that died (both ends count their own). |
| `pool_conns` | Since 2.4.18. One entry per open pool connection, oldest first: `age_s`, `tx` and `rx` (datagrams), `queue`, `stalled_ms` (how long its current socket write has been blocked). Uneven `tx` deltas show a skewed spread. |
| `pool_slow_closed` | Since 2.4.7, pool carriers. Pool connections this process closed for delivering far below their share (see [Stalled pool connections](#stalled-pool-connections-245)). |
| `cc` | Since 2.4.10. Pacer diagnostics, see below. |

**The `cc` object (2.4.10).** What held the sender back and why it slowed. Counters run since the start (summed over
sessions); compare two reads to see what happens now.

| Field | Meaning |
|---|---|
| `ticks` | 50 ms pacer ticks. |
| `tok_limited`, `cwnd_limited`, `app_limited` | Ticks in which the sender was held by its pace (rate tokens), by its window, or had nothing to send. Mostly `app_limited` means the tunnel is not the bottleneck. |
| `loss_cuts`, `delay_cuts` | Rate cuts caused by loss and by delay. Since 2.4.11 a reliable carrier (tcp/tls/ws/wss/h2/h2c/grpc) should show `delay_cuts` 0. |
| `deep_trips` | Times the delay rule let the rate fall below the start rate (the 2.4.2 deep-queue signal). |
| `lost`, `spurious` | Packets declared lost, and how many of them were acked later after all (the carrier's TCP delivered them late). |
| `floor_bps` | The current rate floor, bytes per second. |
| `cwnd` | The current window, bytes. |
| `loss_time_ms`, `pto_ms` | The loss timer and the probe timeout now in use. |
| `loss_timer_x` | Reliable carriers: how far the loss timer is stretched (1-8x) because retransmits kept turning out spurious. |
| `pool_full` | Since 2.4.18. Ticks in which the session held back because every pool connection's queue was full (the pool's backpressure). |
| `win_blocked` | Streams that have data to send but no window from the peer right now (a gauge, not a counter). A high value means the receiving side reads slowly. |

With `sessions` > 1 (client) the top-level numbers cover all sessions: counters, `rate_bps`, `ceiling_bps`, `streams`
and `inflight` are sums, `srtt_ms` is the median of the live sessions, `min_rtt_ms` the smallest, `loss_pct` the
highest, and `last_rx_age_ms` the newest packet on any session.

The process also logs a stats line every 10 seconds when something moves (it includes `ceiling=` and `loss=`).

### Speed test (1.8.1)

On a client, `GET /speedtest?dir=down|up&mb=N` (on the `metrics` address, N 1 to 256, default 10) moves N MB through
the live session and returns `{"dir","bytes","seconds","mb_per_s","mbit_per_s","ok","error"}`. The stream asks the
server for target port 0, which the server answers itself (it sends or absorbs the bytes), so no test service or
extra port is needed and the allowlist is not involved. Both ends need 1.8.1 or newer.
`wattun test NAME` runs it 10 MB each way. Since 2.3.0 the answer also has `"sessions"`: with `sessions` > 1 the
test opens one stream on every live session at once, each moving its share of N MB, and reports the total over the
wall time.

### Several sessions (2.3.0)

`sessions: N` (client only; the server needs no change, it already tells sessions apart by their random id) runs N
independent sessions to the same server, each with its own carrier (`conns` connections of a pool carrier, or its own
udp socket), its own pacer and its own session id. Why: one session has one receive goroutine and one send
goroutine, and every stream starts with a 4 MB flow-control window (2.4.0 grows it, see below; before that one stream moved at
most about 4 MB / RTT) (measured on a simulated lossless link: 59 MB/s at 40 ms, 29 at 100 ms, 15 at 200 ms). Through a CDN
from Iran the RTT under load is far above the ICMP path's 40 ms, which is what kept one session at 16-18 MB/s while
separate processes added up.

- New TCP connections go to the live session with the fewest open streams, then the fewest bytes in flight; ties
  rotate. A session that is down (nothing heard for 10 s) gets no new streams while another is up; it reconnects
  by itself as before.
- UDP flows stick to one session, chosen by a hash of the flow id (so a flow's datagrams stay in order); only while
  that session is down does the flow use the next live one.
- With several `peer` addresses the sessions share one TLS engine (fingerprint, ECH state and cache) and one view of
  which edges work; session k's connections continue the edge rotation where session k-1's stopped.
- Every session counts against the server's limit of 32 sessions (a handover runs two clients), hence the cap of 16.
- Not for `icmp`, bonded carriers (`a+b`) or `reverse`: the client refuses to start with a clear message.
- Wire: nothing new. The server has always run one session per session id (that is how the two slots of a
  handover share it), so any 2.x server serves a multi-session client.

### Stream window auto-tuning and cheaper receive path (2.4.0)

- **Per-stream window.** Every stream still starts with the implicit 4 MB window, so an old peer behaves exactly as
  before. The receiver now grows the window it advertises (the existing window frame, nothing new on the wire): once
  per RTT it checks how much arrived; if the sender filled at least half the window and the reader is keeping up
  (under a quarter of the window unread), the window doubles toward 2x the bytes per RTT, up to **16 MB per stream**
  and **64 MB of growth per session** (beyond the 4 MB bases). A lagging reader stops the growth, and an advertised
  limit is never taken back. The sender accepts whatever the window frame says and lets `Write` buffer that much.
  A one-stream download is no longer capped at 4 MB / RTT: on a simulated lossless 150 ms RTT link one stream went
  from 20.5 to 32.7 MB/s (`TestStreamWindowAutoTune`; a 40 MB/s link, so the new figure is link-limited).
  Compatibility: only the receiving end decides, so the gain needs the *receiver* of the bulk data to be 2.4.0
  (a 2.3.x receiver never advertises more than 4 MB, and a 2.3.x sender never buffers more than 4 MB, so either
  one keeps the old limit).
- **Pool carriers, receive side.** `tcp|tls|ws|wss|h2|h2c|grpc` read each connection into 64 KB slabs and hand the
  datagrams out as slices of them: no bufio copy and no allocation per datagram. The gRPC reader moves a message
  straight into the caller's buffer (no staging copy). Smaller bufio buffers for the ws/grpc readers were tried and
  measured no better. Write coalescing was already there (each connection's writer fills a 64 KB buffer and flushes when its
  queue runs dry); a yield before the flush to gather more was measured and gave nothing, so it is not in.
- **GC.** 2.4.0 to 2.4.5 set the GC target to 200 % unless `GOGC` was set. 2.4.6 uses Go's default (100 %) again:
  on a busy CDN tunnel 200 % let the heap reach about 1 GB for 400 MB of live data, and the GC itself took under
  0.1 % CPU. `GOGC` and `GOMEMLIMIT` still override it.
- **`GOMEMLIMIT` needs room.** Set it to at least twice the tunnel's normal heap, or leave it unset. Close to the
  heap, Go collects almost without pause: an Iran client limited to 256 MiB with a ~210-280 MB heap (ICMP, ~300
  connections, 2.4.7) used 75-130 % CPU. With 768 MiB, the 2.4.8 client next to it used about 20 % CPU and 76 MB
  RSS at ~200 connections (2026-10-12).
- **Forwarding buffers (2.4.8).** The two copy buffers of each forwarded connection start at 4 KB and double, up to
  32 KB, only while reads fill them. At ~1,300 connections the fixed 32 KB buffers were 41 MB of Kharej's 197 MB heap
  and 20 MB of Iran's 214 MB.

### Memory with slow readers (2.4.3)

When a user's own connection reads slower than the tunnel delivers, which is typical for mobile users, each stream
used to park its full 4 MB window at the receiver. The sender, blocked by that window, buffered another 4 MB in a
backing array of up to 8 MB. Field, 2026-10-12 (production CDN, 180 streams): 761 MB of live heap on Kharej
(`Stream.makeRoom`) and 625 MB on Iran (`Stream.appendReady`).

- **Receiver.** Once per RTT, if unread data keeps piling up, the stream advertises only 2 RTTs of what its reader
  actually consumed (at least 256 KB). When the backlog runs dry the window grows back by half, up to the normal
  window. A fast reader is never limited, because the window only shrinks while the reader is the bottleneck. The
  advertised limit is never taken back, updates just pause, so an older sender works unchanged.
- **Sender.** `Write` buffers at most 256 KB beyond what the peer's window lets it send, and the send buffer never
  grows past its cap.
- **Both ends.** A big backing array is given back once the stream needs much less.

On a simulated 150 ms link with a reader at about 2 MB/s, the receiver's backlog went from 4 MB to 0.2-0.3 MB and the
sender's from 4 MB to under 0.5 MB, while a fast single stream still reached 32.7 MB/s
(`TestSlowReaderBuffersBounded`, `TestStreamWindowAutoTune`). Each half works on its own: a 2.4.3 receiver
saves the receiver's memory, and a 2.4.3 sender saves the sender's.

Field result, the same production tunnel 26 minutes after the update: Kharej RSS went from 806 to 74 MB, Iran's from
808 to 75 MB.

**2.4.4.** In 2.4.3 the sender gave back an oversized buffer whenever it was more than twice what it needed. That
need moves with every ack, so the buffer was copied again on almost every ack. A single slow stream allocated about
6.6 GB in 8 s, and Kharej's `wattun` threads rose from 2-13 % to 40-73 % CPU under load. The buffer is now given back
at most once a second per stream, and only when it is over 4x the need. That is 142 MB allocated in the same test.
`TestSlowReaderBuffersBounded` now fails above 1 GB.

**2.4.6.** A drained stream used to keep up to 1 MB of buffer in each direction for reuse. On a busy tunnel most
streams are idle keep-alive connections, and 220 of them held about 190 MB on the receiving end (field heap profile,
2.4.5). The kept buffer is now at most 256 KB. `BenchmarkSessionBulk` on 2 CPUs measured 68.5 vs 68.9 MB/s, which is
within noise.

Field result, production CDN with about 250 user connections, 2026-10-12: Iran RSS went from 997 MB on 2.4.5 (22 min)
to 79-100 MB on 2.4.6 (25-29 min, peak 207 MB), and Kharej from 415 MB (peak 551) to 75-103 MB (peak 276). Live heap
was about 80 MB on each end. The 30 s download loop averaged 40.8 MB/s, within the time-of-day range of 2.4.5.
Note that 2.4.3 had also looked fine at 26 minutes (75 MB) and grew to about 630 MB by 52 minutes; 2.4.6 has been
checked up to 29 minutes.

### Streams whose connection closed (2.4.17)

A stream used to be retired only once the local side had read every byte the peer sent. When the local connection
closed while data was still buffered, or while the peer was still sending, that never happened: the stream stayed in
the session with no connection behind it. Field, 2026-10-13 (CDN client after a load test): Iran kept 69-76 open
streams with 0 TCP connections on the port, and RSS grew from 40 to 159 MB in 36 minutes.

From 2.4.17 the forwarder closes the stream's receive side when its connection ends (`Stream.CloseRead`). Unread data
is dropped, so it no longer blocks retirement. If the peer had not finished sending, the stream is reset, so the
peer stops too. A cleanly closed connection is unchanged, and the send direction is never cut short. Both roles use
the same forwarder, so update both ends. Nothing changes on the wire (`TestCloseReadReapsLingeringStream`).

Field result, 2.4.17 (test CDN tunnel, 50-connection load, 2026-10-13): Iran held exactly 50 streams during the load
(2.4.16 climbed from 60 to 91) and both ends dropped to 0 when it stopped, staying there for the 8 minutes checked.
Iran RSS stayed at 33-43 MB during the load (2.4.16: 40 to 159 MB) and fell back to 32 MB afterwards. Throughput
and RTT were unchanged.

## Pacing on TCP-based and CDN carriers

Since 2.4.11 these carriers are paced by delivery rate, see [Delivery-rate pacing](#delivery-rate-pacing-2411); this
section describes the delay pacer they used before (still used for ICMP and UDP, and with `WAT_REL_V1=1`).

TCP never drops a datagram by itself, so on `tcp`, `tls`, `ws`, `wss`, `h2`, `h2c` and `grpc` the pacer judges delay
by each 50 ms interval's fastest sample and allows a third of the base RTT, because CDN edges and TCP buffering add
delay without any queue of ours.

- **2.4.1.** The pace never drops below the start rate (8 MB/s per session), and delay cuts apply only while the
  session fills its window, so bursty web traffic is not cut down to a crawl.
- **2.4.2.** The window is sized from at most 1.5 x the base RTT, not the smoothed RTT, which includes our own queue.
  Two signals can now take the pace below the start-rate floor for about 30 s, down to the configured floor (200
  KB/s):
  - an interval whose fastest sample is above twice the base RTT (and at least 40 ms above it) while the window is
    full;
  - an interval in which at least 4 packets, and at least 1/20 of those sent, waited past the loss timer (400 ms).
    This cuts the pace by 20 %.

  Before 2.4.2, four sessions at the 8 MB/s floor kept pushing at least 32 MB/s into a CDN path that sustained about
  10 MB/s. Cloudflare buffered the excess until packets timed out. Sustained downloads fell from 40-50 to about
  10 MB/s, with 500 ms stalls (field measurement, 2026-10-12). The change is sender-side only and changes nothing on
  the wire. It matters most on Kharej, which sends the downloads, but update both ends.

### Late delivery is not loss (2.4.9, 2.4.10)

Through a CDN, TCP's own retransmits can delay a datagram past the tunnel's loss timer. The tunnel then resends a
packet TCP was about to deliver, and both copies arrive. Field, 2026-10-12 (wss through Cloudflare): Kharej resent
about half its packets while its TCP connections were clean, the 2.4.2 loss rule read that as congestion, and all four
sessions sat at the floor (about 41 down to about 1 MB/s).

- **2.4.9.** A packet declared lost and then acked anyway counts as *spurious*, and is removed from the loss signal.
  While a tick's losses are mostly spurious (at least half), the loss timer stretches by 1.25x per tick, up to 8x,
  and it shrinks back slowly once they are not. Real loss (at least 4 packets and 1/20 of a tick's packets, after the
  spurious ones are removed) cuts the rate by 20 % and sets a ceiling that creeps back up, instead of dropping to
  the floor.
- **2.4.10.** 2.4.9 rarely matched a late ack, because the given-up packet was forgotten before its ack came back.
  Given-up packets are now kept for 5 s, so the late ack is matched. 2.4.10 also added the `/stats` `cc` object
  (see [Metrics](#metrics)).

Reliable carriers only: ICMP and UDP keep the old rule. On an emulated CDN link resends fell from 6-12 % to about
3 %. These two releases did not fix the field slowdown on their own: the `cc` counters showed the cause was delay
cuts, which 2.4.11 removed. `WAT_REL_V1=1` restores the pre-2.4.9 rule.

### Delivery-rate pacing (2.4.11)

Through 2.4.10 the pacer judged TCP-based carriers by delay, like the ICMP path. On a real CDN that failed: TCP does
its own congestion control and its retransmits delay a datagram without any queue of ours, so the measured round trip
jitters between 1x and 5x the base RTT. The pacer read that jitter as congestion and cut, and a single CDN stream sat
at about 1 MB/s with hundreds of delay cuts to one loss cut while the TCP socket below it was idle (field 2026-10-13).

From 2.4.11 the reliable carriers are paced by **delivery rate** instead, which TCP's jitter and retransmits do not
disturb:

- The sender counts bytes acked per second and keeps the windowed maximum over about ten round trips (busy intervals
  only, so an idle lull never lowers it, and a burst of acks released by a stalled connection is averaged over at
  least one RTT so it does not inflate it). This is the path's delivery capacity.
- The pace tracks `relBWGain` (1.2x) above that estimate, and inflight is bounded to `relCwndBDP` (3) bandwidth-delay
  products, so over-pacing becomes window-limited headroom that probes for a little more without inflating latency.
- Delay never cuts a reliable carrier now. Genuine wire loss still does, through the 2.4.9 rule below (a gentle
  multiplicative cut with a ceiling that creeps back up), after spurious retransmits are removed.
- A slow last leg behind a deep CDN buffer (the 2.4.2 case) is handled by the same BDP bound: delivery plateaus at the
  drain rate, so the estimate and the pace stop climbing and inflight stays near one BDP, instead of queueing until
  packets time out. The 2.4.1/2.4.2 floor-drop rules above apply only to the pre-2.4.11 delay pacer, still used for
  ICMP and UDP and reachable with `WAT_REL_V1=1`.

On an emulated CDN link (shallow edge buffer, 90 ms base RTT, per-connection stalls) this took a single flow from
about 1 to 5-7 MB/s and a parallel download from under 1 to 10-14 MB/s, with no delay cuts. The `/stats` `cc` object
(2.4.10) reports the live picture: `delay_cuts`, `deep_trips`, `loss_cuts`, `spurious` of `lost`, what limited the
sender each tick, and the window and loss-timer gauges.

**Draining to re-measure the base RTT (2.4.12, corrected in 2.4.13).** The BDP bound is `maxBW x minRTT`, so it needs
a true `minRTT`. A single, deeply queued connection never delivers a drained sample, so `minRTT` climbed with its own
queue and the window ran away with it (field 2026-10-13: `minRTT` rose to 550 ms from a real 108, inflight over a
megabyte). Every 8 s (just under the 10 s `minRTT` window, so a sample is always fresh) the pacer enters a BBR-style
PROBE_RTT: it caps inflight to a few packets (`cwnd` returns the drain floor, 4 packets), **waits for inflight to
actually reach that floor**, then holds there ~1 RTT so `sample` reads the base with the queue empty. 2.4.12's first
cut drained only to half a BDP, which on a large queue is still a large queue -- the field showed `minRTT` stuck at
314 ms and the window still running away, so the drain floor is now fixed and low, and the queue depth is read from
the live inflight (mirrored into the pacer). A sample may raise `minRTT` only while draining *and* with inflight at
the floor; otherwise `minRTT` only ever falls, so a queued sample can never pull the base RTT up. On a clean single
connection this holds `minRTT` at the true base and lets a lone stream fill ~90 % of the link; the leftover gap under
heavy per-connection stalls is single-connection head-of-line blocking, which the production pool (8 connections)
routes around.

A drain cycle is entered only when a standing queue of our own could be hiding the base, which takes **both** of two
conditions (2.4.16):

- **inflight above twice the drain floor** -- this sender is holding a real queue. An app-limited sender (the receive
  side of a transfer, or an idle session) sits at the floor, builds no queue, and its delayed samples are reverse-path
  or scheduling noise, never a base to re-measure from. Draining there once raised a client's `minRTT` from 107 to
  545 ms *while it was only receiving a download* and wrecked its next upload (the window sized from a 545 ms base
  queued to a 5 s `srtt` and the stream reset; field 2026-10-13). Requiring inflight above the floor also means the
  `minRTT` raise in `sample` can fire only after a genuine drain down from a real queue.
- **`srtt` above `minRTT x 1.5`** -- there is actually a queue to clear. A pool session runs at `srtt ~ minRTT` (its
  many connections keep each one's queue shallow and `minRTT` fresh), so it skips the drain and its throughput dip; a
  single queued connection sits far above and drains every cycle.

The two conditions were added separately and each alone was wrong: 2.4.14 gated on `srtt` only and let an app-limited
sender re-measure off noise (broke uploads); 2.4.15 gated on inflight only and so drained pool sessions every cycle
(cost pool throughput). 2.4.16 requires both.

**Field result, 2.4.16** (test CDN tunnel through Cloudflare, 2026-10-13). Pool sessions kept `srtt` at 109-116 ms
against a 86 ms `minRTT` instead of drifting up over time, with no delay cuts. Pool speed tests: 22.6 and 32.4 MB/s
up. A single connection: 24.4 MB/s down on a 28-32 ms Cloudflare edge, and 4.41 MB/s up where 2.4.14 had reset the
stream. The slow single-connection results seen earlier (0.6-0.8 MB/s) were on an 84 ms edge, which is why the
manager's edge scan matters.

### Direct pools (2.4.18)

A pool carrier with no CDN in between (`tcp` or `tls` direct, or any pool carrier with `reverse`) is "direct": the
only queues are the pool's and the kernel's, and both push back. 2.4.18 changes how such a tunnel sends; CDN tunnels
(ws/wss/h2/grpc direct to a CDN edge) keep the 2.4.17 behaviour except where noted. Field results, reverse tcp,
Kharej → Iran (the direction with heavy random loss, 3-14 % kernel retransmits), 200 MB per run:

| Change | Before | After |
|---|---|---|
| BBR on pool sockets (`tcp-cc`) | upload 12 MB/s | upload 47-56 MB/s |
| Late ACKs | download 8 streams 30.5, 16 streams 27.8 MB/s; 61-82k resends | 49-51 and 64.7 MB/s; 0-1.7k resends |
| Warm tunnel, 16 conns, 32 streams | | 68.9-73.8 MB/s |

Raw TCP on the same path (8 BBR connections, no tunnel) moved 78 MB/s; 32 connections 127 MB/s.

- **BBR.** The kernel default cubic halves a connection's window on every lost segment, and on this path loss is
  random, not congestion: 8 raw cubic connections moved 2.5 MB/s, 8 BBR ones 78. Pool sockets now ask for BBR
  (`tcp-cc`). Local to each end.
- **Late ACKs** (receiver only). A stalled pool connection leaves a hole for every packet it carries. An ACK frame
  names only the newest 64 received ranges, so those packets, arriving later and lower, were never acked and the
  sender resent them all: resends grew with the stream count. Each ACK now first carries a frame with the received
  packets the main frame leaves out, with a one-hour ack delay so no sender version takes an RTT sample or declares
  a loss from it. Works against any peer version; only the receiver of a direction needs 2.4.18.
  `WAT_NO_LATEACK=1` turns it off.
- **Replay window** 16384 → 131072 packets on reliable carriers (a 1 MB ring per session): at 32 connections a
  connection in loss recovery outlasted the old window and its delivered packets were dropped as replays.
- **Pool backpressure.** A full pool queue used to drop the packet silently (the session resent it after its loss
  timer). The session now waits while every connection's queue holds 16 packets or more (`pool_full`;
  `WAT_POOL_BACKLOG` sets the depth, `WAT_NO_BACKLOG=1` restores the old behaviour).
- **Window and timers.** A direct session's window is one second of delivery rather than 3 bandwidth-delay
  products, it skips the minRTT drain, and the pool keeps slow connections (TCP recovering is not a slow path).
  When a pool connection dies, its unacked packets are resent at once instead of after the loss timer.
  `WAT_NO_DIRECT=1` turns direct mode off.
- **Startup.** A direct session paces at 2.5x its delivery estimate until the estimate stops growing (a fresh
  tunnel's first 200 MB ran at 42-45 MB/s, the next at 53-71).
- **Pinning.** Each stream rides one pool connection, assigned round-robin, as separate TCP connections would; a
  packet with interactive data takes the least queued connection, so ping under a full download stayed at the
  38-40 ms base. Resent data goes on any connection. `WAT_NO_PIN=1` sprays every packet instead (about the same
  speed in the field).
- **Loss cuts off.** A direct pool no longer cuts its rate on loss (TCP's loss is not ours; `WAT_REL_LOSSCUT=1`
  restores it), and its window also covers 2 x srtt (`WAT_CWND_MINRTT=1` turns that off). CDN tunnels keep the
  2.4.17 rules for both.
- **Speed test** takes `streams=N` (1-32, default 8): `/speedtest?dir=down&mb=200&streams=16`. One stream rides one
  pool connection now, so a single-stream test shows one connection's speed.
- **More connections.** `conns: 16` beat 8 on this path (73.8 against 51 MB/s); 32 fell to 26 MB/s from loss
  bursts. Both ends update for the full gain; the pool's own sending changes are local to each end.

### Stalled pool connections (2.4.5)

Through a CDN, one edge connection can sit in TCP retransmit backoff for tens of seconds with megabytes queued in the
kernel while the others flow. In the field on 2026-10-12, Kharej showed connections with `backoff:8` and up to 5 MB of
Send-Q. The pool picks the connection with the shortest queue of its own, and a stalled socket still swallows writes
into the kernel, so it kept getting picked. Every packet sent there was lost for 400+ ms, and its streams waited:
9-12 % loss, 1 s freezes even at idle, and downloads of 2.5-7 MB/s. 2.4.4 made this visible: 2.4.3's CPU waste had
throttled the sender enough to hide it.

- Each pool socket gets `TCP_NOTSENT_LOWAT` of 128 KB (Linux), so a stalled connection blocks its writer instead of
  queueing megabytes.
- A connection whose socket write has been blocked for more than 300 ms is skipped while any healthy connection
  exists. If every connection is stalled, the path itself is slow, and the pool keeps sending as before.
- A connection stuck for more than 5 s while a healthy one exists is closed, and the client redials it.

This is local to each end and changes nothing on the wire.

**2.4.7.** A connection can also stay writable but deliver little (a slow edge or path). Every second each end counts
what every pool connection delivered. Once the pool has at least 3 connections older than 3 s and enough traffic to
judge, a connection that delivered under half the typical count (the upper quartile) for 3 seconds in a row is
closed, at most one per second, and the client redials it through a fresh path. `pool_slow_closed` in `/stats`
counts these. It works with any peer version, because it only closes connections.

Field result, production CDN, 2026-10-12, measured back to back the same morning: the 30 s download loop averaged
30.4 MB/s on 2.4.3 and 42.9 / 44.7 MB/s on 2.4.5, at 2 and 21 minutes after the restart. Kharej showed no connection
in backoff, and the p95 of a small request during the loop fell from 1114 ms to 269-549 ms.

## ICMP path limits and pacing

Measured 2026-10-10 on the real Iran <-> Kharej path (only ICMP passes):

- The path delivers at most about 50-55k ICMP packets per second Kharej -> Iran (about 33 MB/s at 640 B payload),
  shared by every ICMP type. Past about 45k pps a queue builds (p99 one-way delay +300 ms) and loss rises. Random
  loss on this path is only about 0.2 %.
- **Packet size (2026-10-12).** The path passes full 1500-byte ICMP packets again, both ways, with DF set: 0-0.5 %
  loss from 640 to 1472 bytes, no fragmentation needed. A route `mtu lock 680` on either end still caps it, so check
  `ip route get <peer>` first. Measured with a test tunnel next to production, same 30 MB/s cap, 3 runs each:

  | `mtu` | Down MB/s | Up MB/s | Kharej retrans (download) | Ping during download, p50/p95 |
  |---|---|---|---|---|
  | 640 (default) | 22-24 | 21-22 | 3.6-4.9 % | 41 / 43 ms |
  | 1400 | 27.5 | 26 | 0.8 % | 41 / 42 ms |

  Larger packets need fewer packets per MB, so they stay further below the packet-rate limit above. Test the size
  with `ping -M do -s SIZE <peer>`, then set `mtu` on **both** ends (each end sends at its own size).
- **Volume limit (2026-10-12).** Twice, ICMP held above ~30 MB/s in total for a few seconds (34.5 and 41.5 MB/s) was
  followed 5-30 s later by a reroute inside Iran (base RTT 40 -> 76 ms) that lasted minutes. On that route bulk
  transfers collapse (~2 MB/s, 50-90 % loss) while light traffic is fine. Runs at or below ~27 MB/s never triggered
  it. Keep the total `max-mbps` of every ICMP tunnel on the path at about 30 or less, whatever the packet size.
- `max-mbps` stays at 16 by default for `icmp` (and any bond that includes it). The ceiling that really binds is the path's packet rate, so values above
  roughly 30 only add queueing.
- **Loss-aware ceiling (1.8.0, opt-in).** Off by default: the pacer is delay-based and loss alone is not congestion.
  With `loss-ceiling: true` (`-loss-ceiling`) it also compares, every 50 ms, the interval's loss with a learned
  baseline (slow average of quiet intervals, at least 0.5 %). If loss is above `max(3 %, 4 x baseline)` the rate is
  cut by 15 % and a soft ceiling is set 5 % above the new rate; the ceiling then rises 2 % per loss-free interval
  and the rate may not climb past it. It helps when a too-high `max-mbps` makes the path drop packets (a test pair
  with `max-mbps 80` ran 30-35 % of the wire as retransmissions). Steady random loss (even 2 %) does not trigger
  it. Intervals with fewer than 50 packets are ignored, and TCP-based carriers never use it. With it off,
  `ceiling_bps` stays 0. Watch `ceiling_bps` and `loss_pct` in `/stats`.
- **Batching is on by default for the ICMP carrier on Linux** (sendmmsg / recvmmsg): one flow went from 15 to
  25 MB/s and CPU per MB from 0.043 to 0.026 on the real path. `WAT_BATCH=0` forces it off; other carriers keep
  batching off unless `WAT_BATCH=1`.
- **`icmp-type`** picks the ICMP message type the tunnel hides in: `echo` (8 request / 0 reply, the default),
  `timestamp` (13/14), `info` (15/16) or `mask` (17/18). The client sends the request type, the server answers with
  the matching reply. The kernel BPF filter accepts only that pair (and the tunnel's identifier range), so other
  ICMP software never sees the packets and an `echo` tunnel is unaffected. Both ends must use the same value.
  Note: Linux itself answers timestamp requests (and echo requests unless `icmp_echo_ignore_all=1`); the kernel's
  extra reply carries our own payload back, fails authentication and is dropped. `info` and `mask` requests are
  ignored by the kernel.

## Handover, drain and rollback

A restart cuts every connection. WatTunnel avoids restarts on a live system.

- **Two clients, one key.** Each client session has its own random id and key, so two Iran instances (slots) can run
  side by side against the same server.
- **Port changes need no restart.** The server re-reads its `ports:` list or `allow-file`. The client re-reads
  `ports:`.
- **Handover.** Start the idle slot on offset ports, prove the link and push data through it, flip
  the NAT redirect from the old slot to the new one, then let the old slot drain.
  If the proof fails, the live slot is not touched.
- **Drain.** `SIGUSR1` to a server stops new sessions. It exits when the last session ends. Stop an old client slot once its `/stats` shows `streams` 0.
- **Rollback.** Every install keeps the previous binary as `wattun.prev`. `wattun` (the manager) can roll back to it.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `alive: false` on both ends, no errors | Wrong key, or the carrier is filtered. Compare the key files (`sha256sum`). Try `ping` between the servers: ICMP must pass. |
| Iran cannot ping Kharej, Kharej can ping Iran (often one day on, one day off) | A one-way block on Iran's own pings. Use `reverse: true` on both ends with `icmp` (see Reverse ICMP). |
| ICMP works with small pings but the tunnel stalls | MTU. Go back to the default 640 on both ends, then test larger sizes with `ping -M do -s SIZE <peer>` before raising `mtu` again. |
| tcp, tls, ws never connect | That carrier is filtered on this path. Check with `nc -vz HOST PORT` from the client. On a path where only ping passes tCP and UDP are cut: use `icmp`. |
| tcp pool connects, then drops after a few packets | A middlebox cuts long TCP flows. Try `tls`, `wss` or `grpc`, or `reverse`. |
| Pool carriers or UDP forwards do not work, the other end is older | Version mismatch. Both ends must run 1.3.0 or newer for pool carriers and 1.2.0 or newer for UDP forwards. Check `wattun -version` on both ends. |
| `listen tcp ...: address already in use` | Another process owns the port. `ss -ltnp \| grep :PORT`. Never start a test on a port a live instance uses; test ports should be 10811 or higher. |
| `restart needed for KEY` in the log | You changed a key other than `ports:`. Only `ports:` is hot-reloaded. Do a handover. |
| Config does not apply | A parse error keeps the old config. The log says `config FILE: line N: ...`. |
| WireGuard (or another UDP VPN) connects, small apps like Telegram work, web pages do not | Its packets are bigger than one tunnel packet. Update both ends to 2.4.19 (big datagrams are split), or set `MTU = 1280` in WireGuard (udp carrier, or icmp with `mtu: 1400`). `dgram_dropped_size` in `/stats` rising confirms it. |
| Slow, high CPU on Iran | Two cores saturate under many processes. Run one instance, not one per port. Check `retrans` and `send_errors` in `/stats`. Lower `max-mbps` only if the link is rate limited. |
| Time or clocks | Authentication does not compare clocks. A server restart starts its packet numbers from the current time so a nonce is never reused, so keep NTP on and never set a server clock back. |
| Foreign traffic on the listener | Expected. Strangers' packets fail authentication and are dropped. |

## Security model

- **Pre-shared key.** Both ends hold the same secret. It is never sent.
- **Per session keys.** Each client session picks a random 8-byte id. The packet key is derived from the secret and
  that id. Packet = `session id | packet number | ChaCha20-Poly1305(frames)`. The nonce is the packet number and is
  never reused: server numbers start at a time-based value with a direction bit set.
- **Authenticate first.** The server creates a session only if a packet authenticates. Garbage, scans and replays of
  another key are dropped without a response.
- **Server checks.** Clients can only reach the target ports on the server's allowlist, and only on `127.0.0.1`.
- **What TLS, wss, h2 and grpc add.** They hide the traffic's shape from a middlebox: it looks like HTTPS, a
  WebSocket or gRPC. They do not add secrecy; the session is already encrypted. With the default self-signed
  certificate the client does not verify the server. The PSK still stops an impostor, because it cannot read or forge
  the session. Set `tls-pin` to also reject a wrong certificate.
- **What none of this hides.** The server's address, the volume and timing of packets, and the fact that ICMP or the
  carrier is in use. WatTunnel is not an anonymity tool.
- **Protect the key file.** `chmod 600`, and do not put the key on the command line (`ps` shows it). 
- **Metrics.** Keep `metrics` on `127.0.0.1`. pprof is on the same address.

## Build and test

```bash
go test -race -count=1 ./wat/                                   # simulated-link and loopback tests
GOOS=linux GOARCH=amd64 go vet ./... && GOOS=linux GOARCH=amd64 go build -o /dev/null ./cmd/wattun
sh build.sh                                                     # dist/ binaries
```

Layout: `wat/` is the library (session, congestion control, streams, carriers), `cmd/wattun` the binary,
`cmd/wprobe` a path probe. Bump `wat/version.go` for every shipped change, and
rebuild `dist/` (`sh build.sh`). A change that is slower on ICMP is not
shipped.

## License and attribution

WatTunnel is released under the MIT License (see [LICENSE](../LICENSE)). It uses `golang.org/x/crypto`, `golang.org/x/net` and
`golang.org/x/sys` (BSD-3-Clause).

Ideas, not code, come from several projects. GOST (MIT licensed) is the comparison baseline and the reference for what a
forwarding tool should offer. Backhaul and BackPack were studied as benchmarks and
for feature ideas; no code from them is copied. The ICMP engines we compared against (pingtunnel, Hans, ptunnel-ng) are
their own projects.
