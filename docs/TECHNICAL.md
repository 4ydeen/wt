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
passes: payload up to about 640 bytes, about 0.2 to 2 % random loss, about 40 ms. Every ready-made engine we tried
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
| `icmp` | Only ping passes (Iran today). | 640 bytes | yes (raw socket) | 4 lanes by default (`lanes`). Pacing is delay-based. The path allows at most about 640 bytes of payload. Do not raise `mtu` above that. |
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

## UDP forwarding

Since 1.2.0 WatTunnel also forwards UDP ports (WireGuard, DNS, QUIC, game servers) as unreliable datagrams inside the
same session. Datagrams are not retransmitted and are dropped when a queue is full. That is correct for UDP.

- Config: add `N/udp` to the `ports:` list on both ends. A plain `N` (or `N/tcp`) is TCP.
- Flag: `-udp PORT` or `-udp listenPort:serverPort[@bind][,...]` on the client.
- The server only forwards to UDP ports that are listed as `/udp`. A TCP-only list allows no UDP.
- Idle flows are closed after `udp-idle` (default 60 s).
- Both ends need wattun 1.2.0 or newer.

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
| `max-mbps` | 16 | both | Pacing ceiling, MB/s per direction. See "ICMP path limits and pacing". |
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
| `-max-mbps F` | 16 | Pace ceiling per direction. |
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
process start.

```json
{"20001": {"bytes_up": 0, "bytes_down": 0, "conns_total": 0, "conns_active": 0, "udp_flows_active": 0,
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
| `alive` | Server: at least one client session (a session closes 45 s after its last packet). Client: an authenticated packet from the server arrived in the last 10 s (each side pings at least every 2 s, so an idle link stays alive). |
| `last_rx_age_ms` | Since 2.0.1. Milliseconds since the last authenticated packet from the peer (server: from any client, including sessions that have closed). `-1` = none since the process started. Monitors should use this rather than ping: it only moves on real tunnel packets. |
| `clients` | Since 2.1.0, servers only. One entry per live client session: `[{"ip":"203.0.113.5","carrier":"tcp","age_ms":1234}]`. Behind a CDN carrier (`ws`, `wss`, `h2`, `h2c`, `grpc`) `ip` is the proxy's address. Auto mode uses it to learn Iran's IP. |
| `sessions` | Server: client sessions. Client: always 1. |
| `draining` | Server: not accepting new sessions. |
| `streams` | Open TCP streams. The drain timer waits for 0. |
| `srtt_ms`, `min_rtt_ms` | Smoothed and minimum round-trip time. |
| `rate_bps` | Current send rate in bytes per second. |
| `ceiling_bps` | Loss-aware soft ceiling in bytes per second (0 = none active). |
| `loss_pct` | Loss in the last judged 50 ms interval, percent (0 until 50 packets were sent in one). |
| `inflight` | Unacknowledged bytes. |
| `pkts_out`, `pkts_in`, `bytes_out`, `bytes_in` | Totals. |
| `retrans` | Retransmitted packets. |
| `fec_sent`, `fec_recovered` | FEC parity packets sent; packets rebuilt from parity. |
| `send_errors` | Carrier send failures. |
| `dgram_sent`, `dgram_recv` | UDP datagrams. |
| `dgram_dropped_queue`, `dgram_dropped_size`, `dgram_dropped_rx` | UDP drops: queue full, too big, bad on receive. |
| `dgram_flows` | Active UDP flows. |
| `dgram_rejected` | UDP flows refused (port not allowed). |
| `dgram_flow_cap_drops` | Datagrams dropped at the flow cap. |

The process also logs a stats line every 10 seconds when something moves (it includes `ceiling=` and `loss=`).

### Speed test (1.8.1)

On a client, `GET /speedtest?dir=down|up&mb=N` (on the `metrics` address, N 1 to 256, default 10) moves N MB through
the live session and returns `{"dir","bytes","seconds","mb_per_s","mbit_per_s","ok","error"}`. The stream asks the
server for target port 0, which the server answers itself (it sends or absorbs the bytes), so no test service or
extra port is needed and the allowlist is not involved. Both ends need 1.8.1 or newer.
`wattun test NAME` runs it 10 MB each way.

## ICMP path limits and pacing

Measured 2026-10-10 on the real Iran <-> Kharej path (only ICMP passes):

- The path delivers at most about 50-55k ICMP packets per second Kharej -> Iran (about 33 MB/s at 640 B payload),
  shared by every ICMP type. Past about 45k pps a queue builds (p99 one-way delay +300 ms) and loss rises. Random
  loss on this path is only about 0.2 %.
- `max-mbps` stays at 16 by default. The ceiling that really binds is the path's packet rate, so values above
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
| ICMP works with small pings but the tunnel stalls | MTU. Keep ICMP at 640. Check that the route MTU is not above about 680 and that nothing drops packets over 700 bytes. |
| tcp, tls, ws never connect | That carrier is filtered on this path. Check with `nc -vz HOST PORT` from the client. On a path where only ping passes tCP and UDP are cut: use `icmp`. |
| tcp pool connects, then drops after a few packets | A middlebox cuts long TCP flows. Try `tls`, `wss` or `grpc`, or `reverse`. |
| Pool carriers or UDP forwards do not work, the other end is older | Version mismatch. Both ends must run 1.3.0 or newer for pool carriers and 1.2.0 or newer for UDP forwards. Check `wattun -version` on both ends. |
| `listen tcp ...: address already in use` | Another process owns the port. `ss -ltnp \| grep :PORT`. Never start a test on a port a live instance uses; test ports should be 10811 or higher. |
| `restart needed for KEY` in the log | You changed a key other than `ports:`. Only `ports:` is hot-reloaded. Do a handover. |
| Config does not apply | A parse error keeps the old config. The log says `config FILE: line N: ...`. |
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
