# WatTunnel

**English** | [فارسی](README.fa.md)

WatTunnel forwards TCP and UDP ports from one server to another over a filtered network. It is a single static Go
binary with no other dependencies. It can carry traffic over:

- **ICMP** (ping). This works even when only ping gets through.
- **UDP, TCP or TLS**.
- **WebSocket, HTTP/2 or gRPC**. These work behind a CDN such as Cloudflare.

Every carrier runs the same encrypted session (ChaCha20-Poly1305 with a pre-shared key), with its own congestion
control, so it stays fast on lossy links.

## How it works

```
users ──► CLIENT (inside server) ══ tunnel (icmp / udp / tcp / tls / ws / grpc …) ══► SERVER (outside server) ──► 127.0.0.1:PORT
```

- The **server** runs on the outside server, where your real service (VPN panel, web server, …) listens.
- The **client** runs on the inside server. Users connect to the client's ports, and each connection is delivered to
  the same port on the server's `127.0.0.1`.

## Install

Run this on **both** servers as root (Linux with systemd, amd64 or arm64):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
```

If GitHub is blocked on a server, put a mirror prefix in front of every download:

```bash
WAT_PROXY=https://ghproxy.net/ bash <(curl -fsSL https://ghproxy.net/https://raw.githubusercontent.com/JohnWatsoon/WatTunnel/main/install.sh)
```

The installer adds `/usr/local/bin/wattun`, the `wattun-manager` menu, a systemd template `wattun@.service` and
`/etc/wattun/`. It doesn't start anything by itself.

## Set up a tunnel

1. On the **outside** server, run `wattun-manager` and choose **1) New server tunnel**. Pick a carrier (ICMP if only
   ping works) and, optionally, the ports clients may reach. It prints the server address, the carrier and a
   **key**.
2. On the **inside** server, run `wattun-manager` and choose **2) New client tunnel**. Enter the same carrier, the
   server address, the key, and the ports to forward (for example `443,8080,53/udp`).
3. The menu shows `link:true` once the two sides are connected. Users can now connect to the inside server's ports.

### Manager menu

| Option | What it does |
|---|---|
| New server / client tunnel | Guided setup. Writes `/etc/wattun/NAME.yml` and `NAME.key`, then starts `wattun@NAME`. |
| Manage a tunnel | Status, live stats, logs, add or remove ports (applied live, no restart), edit the config, restart, stop, start, show the key, delete. |
| Update | Installs the latest release and keeps the old binary for rollback. |
| Roll back | Swaps back to the previous binary. |
| Uninstall | Stops every tunnel and removes WatTunnel. |

Shortcuts: `wattun-manager list`, `wattun-manager update`, `wattun-manager rollback`.

## Choosing a carrier

| Carrier | Use when | Notes |
|---|---|---|
| `icmp` | Only ping passes | Needs root on both sides. Use the default MTU (640). |
| `udp` | UDP works | Lowest CPU use and latency. |
| `tcp` / `tls` | TCP works / HTTPS must be seen | Uses a pool of connections. |
| `ws` / `wss` / `h2` / `h2c` / `grpc` | Behind a CDN or reverse proxy | Set `sni` / `host` / `path` in the config file. |

Reverse mode (the inside server listens and the outside server dials), UDP forwarding, FEC, per-port limits, metrics
and every config key are covered in [docs/TECHNICAL.md](docs/TECHNICAL.md).

## Configuration

Each tunnel is one file at `/etc/wattun/NAME.yml`. Changes to `ports:` are picked up within 3 seconds. Any other
change needs a restart (`systemctl restart wattun@NAME`).

```yaml
mode: client
key-file: /etc/wattun/client.key
carrier: icmp
peer: 203.0.113.10
metrics: 127.0.0.1:19700
ports:
  - 443
  - 53/udp
```

Useful commands:

```bash
systemctl status wattun@NAME
journalctl -u wattun@NAME -f
curl -s 127.0.0.1:19700/stats
```

## Build from source

You need Go 1.26 or newer.

```bash
git clone https://github.com/JohnWatsoon/WatTunnel && cd WatTunnel
sh build.sh                 # dist/wattun-linux-amd64 and dist/wattun-linux-arm64
go test ./...
sudo bash install.sh        # installs the binary you just built
```

## Security

- Keep the key secret. The key files are `chmod 600`.
- Strangers' packets fail authentication and are dropped without a reply.
- The server only forwards to `127.0.0.1`, and only to ports on its allowlist.
- WatTunnel encrypts and authenticates traffic. It doesn't hide that a tunnel exists, and it isn't an anonymity tool.

## License

[MIT](LICENSE)
