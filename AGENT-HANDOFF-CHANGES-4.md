# WatTunnel 2.8.1 - refinement round, step 1 + step 2 (branch `dev`)

Handoff for the next agent. `NEXT-AGENT-PROMPT.md` is the mission; this file is what actually landed.

## Step 1 - refinement of rounds 2.6.0-2.8.0 (commit `cc8cc3c`)

- `rotateDue` compared the byte budget against the DATAGRAM COUNT (~256x off at the 4096-byte pool MTU):
  now real bytes via `txSize`. New `rotatePick`: one recycle per tick, oldest-first, never drops the
  last usable connection.
- `Clone` dropped the dial hook (`carrier_tcp.go`): `n.hook.Store(c.hook.Load())` - every session
  beyond the first dialed bare, so `-fake-sni` only fired on session 1.
- Fake-SNI was dead on `tls`/`wss`/`h2`/`grpc`: `Wrap` unwraps the TLS/framing wrapper (`rawTCP`) instead
  of asserting a bare `*net.TCPConn`.
- `-pool-rotate-bytes` (`cmd/wattun/main.go`, `parseSize` suffixes, decimal units).
- `sumSeq` mirror base is per connection (two pool connections opening at once cross-set each other's).
- Tests in `wat/rotate_test.go`.

## Step 2 - `wattun-manager` resilient-UX redesign (this round)

One "resilience options" block instead of two scattered places, plus recallable profiles:

- Wizard (Iran, pool carrier, Linux): fake-sni name / mode (`seq|ttl|sum|seqsum`) / ttl, then
  `pool-rotate` and `pool-rotate-bytes`, all with `bin_ver_ok` guards. Profile pick happens first.
- Advanced settings: key `k` renamed "resilience" - the same five values, plus summary lines
  (`fake-sni`, `pool-rotate`, `pool-rotate-bytes`).
- `profile save|list|show|del|apply [NAME] [TUNNEL]`: writes `$CONF/profiles/NAME.env`
  (`FAKESNI/FAKEMODE/FAKETTL/POOLROT/POOLBYTES`, comments ignored on read, atomic `mv`), re-applies it
  to a tunnel and restarts it. Reaches users as `wattun profile ...` too: any non-flag first argument
  execs into the manager (`cmd/wattun/manager_unix.go`).
- Unattended: `--fake-mode seqsum`, `--pool-rotate`, `--pool-rotate-bytes`. **Latent bug fixed**: the
  `ni_parse` first case `--*)` swallowed `--fake-sni/--fake-mode/--fake-ttl`, so those flags always died
  with "Unknown option"; the value list now routes them into the value branch.
- Validators: `v_pool_rotate` (Go `time.ParseDuration` durations), `v_pool_bytes` (mirrors Go
  `parseSize`: case-insensitive, optional `B`, decimals), `v_fake_mode` (+`seqsum`).
- `MGR_VERSION=2026102001`.
- `test-manager.sh`: one runnable check (assert-based, no root/systemd/binary) for profiles, apply/clear,
  unattended flags and the validators. Run `bash test-manager.sh`.

**Guard style is HARD on purpose.** The config loader rejects unknown keys (`config.go:164`), so a
`pool-rotate:` line written for a 2.7.x binary makes the tunnel REFUSE TO START. Config keys are flag
names (`flag.Lookup`), so `pool-rotate` / `pool-rotate-bytes` need no Go change.

Also fixed a test-only flake: `TestWriteLoopCountsBytes` kept the accepted conn in `_`, so the GC
finalizer closed it and the writer saw a dead connection under `-count>1`.

## Docs synced

- `wat/version.go` 2.8.1; release badges in both READMEs.
- `docs/TECHNICAL.md`: `pool-rotate-bytes` row, 2.8.1 release-history entry, `wattun profile ...` in the
  manager command block, advanced-settings bullet mentions resilience.
- `README.md` / `README.fa.md`: fake-SNI line now names `seqsum` and the byte budget, native Farsi.

## Verification (Windows box)

- `bash -n wattun-manager`, `bash -n install.sh`, `bash test-manager.sh` -> ALL OK, exit 0.
- `go build ./...`, `go vet ./...`, `GOOS=linux go vet ./wat/ ./cmd/wattun` -> clean.
- `go test ./cmd/wattun/` -> ok. `go test ./wat/ -run 'Rotate|Clone|WriteLoopCounts|SumSeq' -count=60` -> ok.
- NOT hardware-tested (needs Linux + CAP_NET_RAW/CAP_NET_ADMIN): real marker transmission, real churn
  recycling, and the wizard's unattended path end to end (needs a real token).

## Next (step 3, in priority order)

1. **Filter telemetry + auto-mode** - probe FIRST (SYN with listed/unlisted SNI, one seq marker, one
   sum marker) -> `/stats` filter profile -> auto-pick the fake mode. No marker IP-fragmentation before
   that probe exists (RESEARCH-3 §3 correction).
2. **ICMP ceiling governor** - ramp until the reroute signature (RTT spike + loss), binary-search down,
   cache per path. Replaces the hardcoded 16 MB/s default.
3. **ECH bootstrap ladder** - fetch the ECHConfigList through the icmp carrier when DoH is hijacked.
4. Byte-axis churn: done in 2.8.1 (`pool-rotate-bytes`) - field-validate next.
5. Push `dev`, tag `v2.8.1`, release notes from the TECHNICAL 2.8.1 entry.
