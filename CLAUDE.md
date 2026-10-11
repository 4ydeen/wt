# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

WatTunnel (`wattun`) forwards TCP/UDP ports from an **Iran** server (client, users connect here) to a **Kharej**
server (server, forwards only to its own `127.0.0.1:PORT`). It was built for a path where only ICMP echo passes
(~640 B payload, 0.2-2 % random loss, ~40 ms), and it also runs over udp/tcp/tls/ws/wss/h2/h2c/grpc. Go module
`github.com/JohnWatsoon/WatTunnel`, Go 1.26, static linux/amd64+arm64 binaries. The user docs are `README.md`,
`README.fa.md` and `docs/TECHNICAL.md` (every config key, flag, `/stats` field, carrier and troubleshooting entry).

## Commands

```bash
go build ./... && go vet ./...
go test -count=1 ./cmd/...                      # fast (~7 s)
go test -count=1 ./wat/                         # simulated-link suite, ~5 min
go test -race -count=1 ./wat/                   # throughput assertions are skipped under -race (race_on_test.go)
go test -count=1 -run 'TestName' ./wat/         # one test
WAT_EMU=udp go test -run TestEmu -v ./wat/      # measuring tool against an emulated bench link, not a gate
sh build.sh [amd64|arm64]                       # reproducible dist/wattun-linux-<arch> + .sha256, prints BUILD_OK <ver>
bash -n install.sh && bash -n wattun-manager    # the shell tooling has no tests; at least syntax-check it
```

On Windows, test an ICMP-free pair locally with two `wattun -config` processes on the `udp` carrier (ICMP needs a
Linux raw socket). Use Windows-style paths (`cygpath -m`) in those config files.

## Architecture

**`wat/`, the transport library.** A `Session` (session.go) is one encrypted connection. It multiplexes reliable
`Stream`s (stream.go, one per forwarded TCP connection) and unreliable datagrams (datagram.go, UDP forwarding) into
packets of frames (wire.go), sealed with ChaCha20-Poly1305 under a per-session key derived from the PSK plus a
random 8-byte session id. Below the session there is one interface. `PacketIO` (io.go) is the client side.
`RawIO` (server.go) is the server side: one socket for all clients, which `Server` demultiplexes by session id.
That is why two clients on one key, the two slots of a handover, never interfere. Each carrier
(`icmp_linux.go`, `carrier_*.go`, `ws.go`) only implements those interfaces. Optional interfaces add capability
without changing the defaults: `Profiled` (MTU and pool hints; ICMP deliberately has none), `BatchSender`
(sendmmsg, on by default for ICMP via `WAT_BATCH`), and `PathFeedback`/`PathChooser` (bonding in bond.go/paths.go).

- **Congestion control (cc.go)** is delay-based: loss never lowers the rate, only RTT growth does. The opt-in
  `-loss-ceiling` is the one exception. Don't "fix" this into loss-based control: on the target path, loss isn't
  congestion.
- **Scheduling (sched.go):** interactive streams go first. Bulk streams are fair-queued by group, where the group
  is the public port (`Stream.SetGroup`).
- **FEC (fec.go)** is adaptive XOR parity, off by default.

**`cmd/wattun/`, the binary.** main.go parses flags and the YAML-subset config (config.go; keys are flag names,
and only the `ports:`/`limits:` lists hot-reload, everything else logs `restart needed`). The client opens a
stream per accepted TCP connection and writes a **2-byte big-endian target port** header. The server checks the
allowlist and dials `127.0.0.1:port` (`serve`/`forward`/`bridge`). Target port **0** is reserved for the
built-in speed test (speedtest.go): the server answers it itself, and the client exposes it as `/speedtest` on the
metrics address. ports.go holds per-port counters, rate limits and quotas. udp.go maps UDP flows onto session
datagrams. The metrics HTTP server (`/stats`, `/ports`, `/speedtest`, pprof) must stay on 127.0.0.1.

**Tooling.** `install.sh` installs the binary from the GitHub release (or `dist/` in a clone, or builds with Go),
checks the sha256, keeps `wattun.prev`, and writes the systemd template `wattun@.service` (`wattun@NAME` runs
`/etc/wattun/NAME.yml`). `wattun-manager` is the interactive bash UI. Roles are Kharej (`mode: server`) and Iran
(`mode: client`). The connection token is `wat1:` + base64 of `carrier|peer|key|path|sni|icmp-type`. It reads
live state only through the tunnel's `/stats` (parsed with grep/sed, no jq). Every screen starts with `page`
(clears the screen only on a tty, then draws the WatsonTUN banner). Auto-heal is the `wattun-heal` systemd
timer calling `wattun-manager heal`. When the installer replaces the manager, it must do an atomic `mv` and the
menu re-`exec`s itself after Update. A running bash script keeps executing its old copy otherwise.

## Rules that are easy to break

- **Wire compatibility.** Old and new peers must keep working together. A new frame type has to be ignorable by an
  older peer (parse stops at unknown types), so put it last in a packet or alone in its own packet, as datagram.go
  and fec.go do. A feature that needs both ends says which version it needs, in code comments and in
  `docs/TECHNICAL.md`.
- **Version and release.** Bump `wat/version.go` for every change to the binary. Pushing a `v*` tag runs
  `.github/workflows/release.yml`, which runs `go test ./...` and `build.sh` and attaches the `dist/` files to the
  GitHub release. The installer downloads `releases/latest`. The manager and installer are served from `main` via
  raw.githubusercontent.com (cached up to 5 minutes), so script changes go live on push, without a tag.
- **Performance.** Changes to the session, cc or carriers must not make the ICMP path slower. The sim tests in
  `wat/` pin the ICMP behaviour, so keep them passing rather than loosening their bounds.
- **Docs.** Keep `README.md` and `README.fa.md` in sync in content. The Farsi README is written natively for
  Persian readers, not translated. Prose goes in `<div dir="rtl">` blocks, code blocks stay outside them, and all
  numbers in the prose are Persian digits. Benchmark figures must come from real measurements (`bench/`, or ones
  the owner reports).
- Shell scripts must keep LF line endings (`.gitattributes` enforces this). Several `.go` files have CRLF in a
  Windows checkout, so `gofmt -l` lists them. That's expected.
