# WatTunnel 2.10.3 — Live-Path Test Report

**Date:** 2026-10-22 (09:00–15:15 Asia/Tehran)
**Author:** JohnWatsoon (session-run)
**Scope:** Real-path verification of the `blackout` branch on two owner-provided temporary VPS. No GitHub release was cut; all testing ran from locally built binaries.

---

## 1. Test bench

| Role | IP | Location | ASN | OS | Notes |
|---|---|---|---|---|---|
| Kharej (server) | 31.57.185.20 | Kerkrade, NL | AS51396 Pfcloud UG | Ubuntu 24.04, 1 core, 894 MB | replacement for 94.183.177.122 (see §8) |
| Iran (client) | 185.84.158.163 | Tehran | AS47216 TookanTech | Ubuntu 24.04 | general internet OK |

Base path: RTT ~83 ms, single TCP/ICMP route, no bonding lanes.

Build: `dist/wattun-linux-amd64` 2.10.2 initially, 2.10.3 (`fcfaa472…`, commit `59ab99e`) after the mid-session fix round. Branch `blackout`, pushed to `origin/blackout`.

SSH access was via a throwaway ed25519 deploy key (`wat-deploy`) installed on both hosts; it must be removed (§9). The Iran host rate-limits SSH logins aggressively — roughly every second connection during the session was refused at handshake or dropped mid-command, which shaped the testing cadence (long cooldowns, batched one-shot scripts).

## 2. Results table

| # | Test | Result | Detail |
|---|---|---|---|
| 1 | Deploy 2.10.2 + configs | ✅ | kharej `tcp :4443` server, iran client `11022→22`, metrics up both ends |
| 2 | Tunnel session established (tcp) | ✅ | `alive:true`, SRTT 85–97 ms, 0 % loss in first ticks |
| 3 | E2E SSH through tunnel (first window) | ✅ | reached kharej sshd twice (password prompt observed) |
| 4 | E2E SSH (later attempts) | ❌ | banner timeout / conn closed after 30–60 s |
| 5 | Built-in speedtest | ❌ | `tunnel is not connected` — tunnel never lived long enough |
| 6 | Raw bulk TCP kharej→iran (5 MB, nc) | ✅ | full 5,000,000 bytes delivered |
| 7 | Raw bulk TCP iran→kharej (5 MB, nc) | ❌ | 8,088 bytes delivered, then flow stalled; second attempt 0 bytes |
| 8 | Slow drip iran→kharej (30 conns × 7 B) | ❌ | 1/30 delivered |
| 9 | Single long conn iran→kharej @10 KB/s | ❌ | 8,088 bytes, identical cutoff |
| 10 | Continuous ping 90 s | ❌ | 0/90 (in a penalty window) |
| 11 | Slow ping 1 per 4–5 s × 12 | ❌ | 0/12 (still penalized) |
| 12 | Single ping after ~5 min cooldown | ✅ | 82.9 ms — penalty box expires |
| 13 | Control: TCP to 4.2.2.4:53 ×5 | ✅ | other destinations unaffected |
| 14 | Control: single TCP/ping to kharej after cooldown | ✅ | path works again |
| 15 | tcp carrier with `-ping-every 12` | ❌ | still flaps alive true/false every 20–40 s |
| 16 | Plain HTTP GET kharej:80 ×6 over 48 s | ✅ | 6/6 HTTP 200 — the only reliable pattern on this path |
| 17 | tls carrier (real cert, pin) | ❌ | TLS handshake completes; first data packet (801 B hello) stuck in Send-Q on all 8 pool conns |
| 18 | tls + fake-sni (`www.mci.ir`, auto probe) | ❌ | probe reports `seq_ok=false sum_ok=false conn_alive=false` — no desync mode passes |
| 19 | h2c carrier on :80 | ❌ | client payloads reach kharej but return path dropped |
| 20 | ws carrier (upgrade looks like HTTP) | ⚠️ | `alive:true` at first; flaps after the upgrade when binary frames flow |
| 21 | 2.10.3 build/vet/tests (`go test ./...`, cmd suite) | ✅ | all green before deploy |

## 3. Path characterization (the important part)

The filter on the Tehran→31.57.185.20 route is **flow-aware and content-aware**, with a penalty box:

1. **New TCP conns pass** the handshake on any port (22, 80, 443, 4443 tested).
2. **Binary payload is dropped bidirectionally** on flows the DPI cannot classify. The bytes leave Iran (Send-Q grows) and never ACK back; the server side often still shows the conn ESTAB — a trap state. The 801–8088-byte stall point varied, so it is not a fixed byte quota but a classification timeout.
3. **Sustained flows of any carrier die in ~30–60 s** — tcp, tls (even with valid cert+pin), h2c, ws, and ICMP all showed the same signature: `out` keeps growing, `in` freezes, `alive:false`, server logs `idle, closing` after its 45 s timer.
4. **Plain HTTP GET on port 80 survives indefinitely** (6/6). The DPI whitelists recognizable HTTP request/response patterns.
5. **ICMP echo is rate-shaped into a penalty box**: steady ping at any rate ≥1 per 4 s collapses to 95–100 % loss; a single ping passes again after ~5 quiet minutes. General internet (4.2.2.4) is unaffected the whole time.
6. **fake-sni desync does not help here**: the auto-probe's own connections die (`conn_alive=false` for all modes), so the path drops unknown payloads even when preceded by a whitelisted SNI ClientHello.

**Conclusion for this specific pair:** no current wattun carrier survives on it beyond ~1 minute. This is a path property, not a transport bug — raw nc and openssl behave exactly like the tunnel. The old kharej (94.183.177.122) was fully blocked; this one is "short-window + penalty box". WatTunnel's sim tests already model harsh links; this bench sits beyond even that.

The practical fix for the user's real deployment is infrastructure, not code: a kharej endpoint whose path does not DPI-kill binary flows (the old AS56971 box worked for months), or fronting through a CDN domain (wss+ECH ladder) which this test could not exercise without a domain.

## 4. Code changes (commit `59ab99e`, branch `blackout`, pushed)

All verified with `go build ./...`, `go vet ./...`, `go test ./cmd/...` (14.5 s), `go test ./wat/` (361.9 s) — green before deploy.

- **`-ping-every` flag / `Config.PingEvery`** (session.go, main.go): the idle keepalive was hard-coded at 2 s (30 pings/min). Live evidence showed periodic packets feed the penalty box; the new knob raises the interval per end. Default unchanged (2 s) so existing deployments behave identically. Docs: flag help carries the rationale; `docs/TECHNICAL.md` still needs a pass on the next docs round.
- **`stream.go` emit() oversize split**: an oversized retransmit frame is now split against the packet room instead of dropping the whole packet. The staged change also fixed a latent compile error (`frameRef.id` → `frameRef.sid`) that was blocking the tree before this round's work could build at all.
- **Path-aware session MTU** (session.go, paths.go, bond.go, server.go — earlier WIP, now committed): a bond path with a smaller MTU caps the datagram room via `PathNextChooser`.
- **`wat/revive.go` + tests**: staged revive-engine work completed and committed with the round.
- Version bumped to **2.10.3**; both VPS run the 2.10.3 binary (`fcfaa472…`).

## 5. What was NOT verified

- Throughput numbers: unobtainable — no carrier lived long enough for the speedtest.
- ac-matrix / wattun-manager from Iran: not run — the manager needs a working tunnel and the SSH rate-limiting made interactive use impossible.
- Hot-reload / drain / quota: not reachable for the same reason.
- wss through a real CDN: needs a domain; not available in this bench.
- udp carrier: not attempted after the path verdict was clear from tcp/tls/h2c/ws — the filter is protocol-agnostic below the whitelist.

## 6. Operational notes for the next agent

- Iran SSH: expect ~50 % handshake refusals during heavy use; batch everything into one `systemd-run` + one-shot script, wait 2–4 min after a refusal.
- `systemd-run --unit=wattun-ir --collect` proved the only reliable way to start the client; compound `nohup … &` commands die with the SSH session.
- Both hosts still hold the `wat-deploy` authorized key; remove it and rotate the root passwords (they appeared in chat).
- Kharej currently runs the `ws` carrier on :80 (last test state); iran's client is stopped.Configs live at `/etc/wattun/{kh,ir}.yml`, keys at `/etc/wattun/t.key`, kharej TLS cert pair (self-signed `www.mci.ir`, sha256 pin `372d3cff…f2c1`) at `/etc/wattun/cert.{pem,key}`.

## 7. Artifacts

- `REPORT.md` (this file)
- `bugs.md` / `RESEARCH.md` / `AGENT-HANDOFF.md`: updated on the next docs pass with this round's entries.

## 8. Old kharej (94.183.177.122) — out of scope, recorded for completeness

AS56971 "Cloud", Amsterdam-registered, fully filtered both directions during this session (TCP 22/80/443/4443, ICMP, UDP all dead from/to Iran). The user supplied 31.57.185.20 as its replacement.

## 9. Cleanup checklist (pending)

- [ ] Remove `wat-deploy` line from `/root/.ssh/authorized_keys` on 31.57.185.20 and 185.84.158.163
- [ ] Delete local `D:\tmpgo\deploykey{,.pub}`
- [ ] Rotate root passwords on both temp VPS (credentials were shared in chat)
- [ ] Tear down or keep the VPS (owner's call — they were bought for this test)
