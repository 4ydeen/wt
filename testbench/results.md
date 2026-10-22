# testbench results — 2026-10-22

Local run of the fake-SNI bench on the Windows checkout. The emulator (`emulate_dpi.py`) is the "censor"; a real
`wattun` server and client (`2.10.4`, commit `7ab0f23`, `dist/wattun-windows-amd64.exe`) move real bytes through
it with the built-in `/speedtest`. The per-mode fake *is* simulated — see "What could not run here".

## Environment

| | |
|---|---|
| host | Windows 11 Pro 10.0.26200, MSYS/MinGW (`MINGW64_NT-10.0-26200`), Git Bash |
| Go / Python / curl | go1.26.3 windows/amd64 / Python 3.14.4 / curl 8.21.0 |
| wattun | 2.10.4 (`wattun 2.10.4 windows/amd64`), built with `sh build.sh windows` |
| link | 127.0.0.1 loopback, 0 ms RTT (the emulator is a userspace TCP proxy; it adds no delay/loss) |
| fake SNI | `www.example.com`, allowlist `www.example.com,cdn.jsdelivr.net` |
| speedtest | `/speedtest?dir=down&mb=4` and `dir=up&mb=4` (speedtest profile: 1 MB) |

## Reproduce

```sh
# from the repo root, Git Bash or any POSIX shell:
sh testbench/measure.sh > testbench/out/measured.csv
sh testbench/measure.sh -m "none seq ttl sum seqsum rst" -r "open smallhello" > testbench/out/measured-extra.csv
sh testbench/measure.sh -m split -r "base wincheck cksumcheck strict throttle open smallhello" > testbench/out/measured-split.csv
sh testbench/measure.sh -m rst -r "base wincheck cksumcheck strict throttle open" > testbench/out/measured-rst.csv
```

`measure.sh` builds the binary if `dist/` is empty, dumps the exact `wat.FakeClientHello` bytes with
`testbench/hello_dump`, runs the emulator's self-test (`SELFTEST OK (33 checks)`), then prints one CSV row per
(mode, rule profile). Logs, `/stats`, `/speedtest` JSON and per-flow JSONL verdicts land in `testbench/out/`.

## What the emulated DPI saw in the hello bytes

`testbench/hello_dump` dumps the real `wat.FakeClientHello`; the emulator classifies those bytes, not a Python
re-implementation:

| SNI | fake ClientHello | TLS record length | parsed SNI | `--max-hello 1000` | `--max-hello 256` |
|---|---|---|---|---|---|
| www.example.com | 359 B | 354 B | www.example.com | passes (TLS to an allowlisted SNI) | dropped (large-hello) |
| cdn.jsdelivr.net | 360 B | 355 B | cdn.jsdelivr.net | passes | dropped |

The fake hello is a complete, parseable TLS 1.3 ClientHello with a correct record length, so an allowlist DPI reads
the allowlisted SNI out of it. It is also only ~360 B, which is why the `smallhello` profile below matters: a filter
whose large-ClientHello threshold is *below* the fake's own size defeats every fake-SNI mode.

## Emulator rule set (profile → flags)

| profile | flags | models |
|---|---|---|
| `base` | `--max-hello 1000 --whitelist www.example.com,cdn.jsdelivr.net` (non-TLS drop on) | allowlist DPI: parses the first flight, does not validate TCP sequence numbers or checksums |
| `wincheck` | base + `--window-check` | DPI that discards out-of-window segments |
| `cksumcheck` | base + `--checksum-check` | DPI that validates TCP checksums |
| `strict` | base + `--window-check --checksum-check --no-reassemble` | DPI that validates all three |
| `throttle` | base + `--throttle-bps 262144 --throttle-after 0 --throttle-dir c2s` | allowlist DPI that throttles an allowed flow's upload to 256 KiB/s per flow |
| `open` | `--allow-nontls --no-whitelist` | no censorship at all (harness ceiling) |
| `smallhello` | base + `--max-hello 256` | DPI that drops any ClientHello over 256 B, allowlist or not |

## Verdicts: does the simulated DPI let the tunnel carry data?

`allow` = the tunnel came alive and both directions completed; `block` = every pool flow was dropped and `/stats`
reported `alive:false`. The rule that decided each flow is from the `DPI_FLOW` JSONL.

| mode | base | wincheck | cksumcheck | strict | throttle | open | smallhello |
|---|---|---|---|---|---|---|---|
| `none` (control) | block | block | block | block | block | **allow** | block |
| `seq` | **allow** | block | **allow** | block | **allow** | **allow** | block |
| `ttl` | **allow** | block | **allow** | block | **allow** | **allow** | block |
| `sum` | **allow** | **allow** | block | block | **allow** | **allow** | block |
| `seqsum` | **allow** | **allow** | **allow** | block | **allow** | **allow** | block |
| `split` | **allow** | block | **allow** | block | **allow** | **allow** | block |
| `rst` | block | block | block | block | block | **allow** | block |

Deciding rule from the flow logs (`testbench/out/flows-*.jsonl`, one JSON line per pool flow):

| mode / profile | rule |
|---|---|
| `seq` / base, `ttl` / base, `sum` / base, `seqsum` / base, `split` / base | `fake-<mode>` → compared on the fake hello's SNI |
| `seq` / wincheck, `ttl` / wincheck, `split` / wincheck, `seqsum` / strict, `sum` / strict, `split` / strict | `no-fake/non-tls` (marker discarded, then the real payload is non-TLS) |
| `sum` / cksumcheck | `no-fake/non-tls` (bad checksum discarded) |
| `split` / smallhello, `seq` / smallhello | `fake-split/large-hello`, `fake-seq/large-hello` (359 B > 256 B) |
| `none` / smallhello | `non-tls` (no fake; the real payload is not TLS) |
| `rst` / base, wincheck, throttle | `rst-cleared/non-tls` (stateful DPI honours the RST, forgets the flow, then drops the non-TLS payload) |
| `rst` / cksumcheck, strict, smallhello | `no-fake/non-tls`, `no-fake/non-tls`, `rst-cleared/non-tls` (checksum-checking DPI ignores the damaged RST; no hello at all) |
| `none` / any profile with the non-TLS rule on | `non-tls` (first client payload is the 8-byte wattun wire header) |

## Rates (default matrix)

`testbench/out/measured.csv` — exact, unedited:

```
mode,sni,dpi_rule,mb_per_s_down,mb_per_s_up,alive,retrans
none,www.example.com,base,0.000,0.000,0,1
none,www.example.com,wincheck,0.000,0.000,0,1
none,www.example.com,cksumcheck,0.000,0.000,0,1
none,www.example.com,strict,0.000,0.000,0,1
none,www.example.com,throttle,0.000,0.000,0,1
seq,www.example.com,base,31.323,29.823,1,1
seq,www.example.com,wincheck,0.000,0.000,0,1
seq,www.example.com,cksumcheck,30.182,27.390,1,1
seq,www.example.com,strict,0.000,0.000,0,1
seq,www.example.com,throttle,12.869,0.637,1,1
ttl,www.example.com,base,30.696,28.930,1,1
ttl,www.example.com,wincheck,0.000,0.000,0,1
ttl,www.example.com,cksumcheck,29.825,30.070,1,1
ttl,www.example.com,strict,0.000,0.000,0,1
ttl,www.example.com,throttle,14.118,0.588,1,130
sum,www.example.com,base,29.251,29.696,1,1
sum,www.example.com,wincheck,29.873,29.881,1,1
sum,www.example.com,cksumcheck,0.000,0.000,0,1
sum,www.example.com,strict,0.000,0.000,0,1
sum,www.example.com,throttle,19.687,0.614,1,112
seqsum,www.example.com,base,28.859,29.550,1,1
seqsum,www.example.com,wincheck,29.690,29.776,1,1
seqsum,www.example.com,cksumcheck,30.378,30.036,1,1
seqsum,www.example.com,strict,0.000,0.000,0,1
seqsum,www.example.com,throttle,14.706,0.595,1,10
rst,www.example.com,base,0.000,0.000,0,1
rst,www.example.com,wincheck,0.000,0.000,0,1
rst,www.example.com,cksumcheck,0.000,0.000,0,1
rst,www.example.com,strict,0.000,0.000,0,1
rst,www.example.com,throttle,0.000,0.000,0,1
```

Supplementary (exact, from `measured-extra.csv` for `open`/`smallhello`, and `measured-split.csv` for `split`; a
second `rst/open` run in `measured-rst.csv` gave 38.128 / 29.876 — run-to-run loopback variance):

```
none,www.example.com,open,30.104,29.770,1,1
none,www.example.com,smallhello,0.000,0.000,0,1
seq,www.example.com,open,29.598,30.116,1,1
seq,www.example.com,smallhello,0.000,0.000,0,1
ttl,www.example.com,open,26.935,30.013,1,1
ttl,www.example.com,smallhello,0.000,0.000,0,1
sum,www.example.com,open,30.077,28.937,1,1
sum,www.example.com,smallhello,0.000,0.000,0,1
seqsum,www.example.com,open,29.743,27.907,1,1
seqsum,www.example.com,smallhello,0.000,0.000,0,1
rst,www.example.com,open,27.366,29.528,1,1
rst,www.example.com,smallhello,0.000,0.000,0,1
split,www.example.com,base,28.826,29.353,1,1
split,www.example.com,wincheck,0.000,0.000,0,1
split,www.example.com,cksumcheck,32.963,29.873,1,1
split,www.example.com,strict,0.000,0.000,0,1
split,www.example.com,throttle,19.953,0.615,1,1
split,www.example.com,open,28.838,29.938,1,1
split,www.example.com,smallhello,0.000,0.000,0,1
```

## Reading the numbers

1. **Harness ceiling ≈ 30 MB/s per direction** (`open` rows, and the `base` rows where the marker is accepted). The
   emulator's proxy does not measurably limit a 4 MB local transfer, so the differences below are the rule, not the
   harness.
2. **The non-TLS rule is what kills the raw tcp carrier without a fake**: `none/base` = 0 MB/s, `alive 0`; the
   first client payload is an 8-byte wattun header, not TLS. That is the control the whole fake-SNI layer exists
   for.
3. **`seq` and `ttl` need a DPI that does not validate windows.** Both pass a `base` DPI at ~30 MB/s and both fail
   the moment `--window-check` is on: the fake sits *below* the stream start (the same wrong-sequence trick in both
   modes; `ttl` differs only in where the packet dies, not in its sequence number). A censor that validates incoming
   sequence numbers defeats both.
4. **`sum` trades the window check for the checksum check.** It passes `wincheck` (in-window sequence) and dies
   under `cksumcheck` (damaged checksum). A NAT/middlebox that validates checksums therefore kills `sum`, exactly
   as documented in `wat/desync.go`.
5. **`seqsum` is the robust single-connector mode in this model**: it survives a DPI that validates windows *or*
   checksums (either marker gets through) and dies only under `strict`, which validates both. That is the rationale
   for spending two fakes per connection.
6. **`split` needs reassembly.** It carries data against a reassembling DPI (and no window check); a DPI that
   parses only the first segment sees a 1-byte TLS byte and then the real non-TLS payload, so it blocks.
7. **`rst` never whitelists a flow.** Against a checksum-checking DPI it is simply invisible and the real payload
   decides (block); against a trusting DPI it clears the flow's state and the re-inspection of the real payload
   decides (block under any non-TLS rule). With censorship off it carries data (~30 MB/s), so it is not a
   whitelisting primitive — its value is clearing stateful middlebox tables, which this emulator models but cannot
   show as a data-carrying verdict.
8. **Throttling shapes the upload hard and the download indirectly.** With 2 pool connections and a per-flow
   upload cap of 256 KiB/s, `throttle` rows carry ~0.59–0.64 MB/s up (≈ 2 × 256 KiB/s, plus token-bucket burst).
   Download falls from ~30 MB/s to 13–20 MB/s even though only client→server is paced, because the session's
   ACKs/control traffic shares that direction; retransmissions rise on the heavily shaped rows (ttl 130, sum 112,
   seqsum 10 at collection time). The tunnel stays alive — it is slow, not blocked.
9. **A large-ClientHello threshold below the fake's own size defeats every mode.** `smallhello` (drop > 256 B)
   blocks `none` and every injected mode, because the fake ClientHello itself is 359–360 B (rule
   `fake-*/large-hello`). The current fake hello is comfortably below a 1000 B threshold but not below a 256 B one;
   a censor measuring hello size at, say, 500 B would still pass it.

## What could not run here (and what that means)

- **The real raw-socket injector did not run.** `wat.NewDesync` is Linux-only (`wat/desync_other.go` returns
  `wat: -fake-sni needs Linux with CAP_NET_RAW`), and this box is Windows with no WSL distribution installed, so
  the local client was started without `-fake-sni`/`-fake-mode`. The emulator models the DPI's *view* of each mode
  (`--inject-fake`, exact `wat.FakeClientHello` bytes) instead. Consequently these results verify the censor-rule
  reasoning and the data path, **not** the AF_PACKET sniffer/raw sender in `wat/desync_linux.go`, and not the
  ordering/timing of the real injected packets.
- **The live Iranian path was not measured here.** `testbench/deploy.sh` is the script for that pair (Iran
  `185.84.158.163` → Kharej `31.57.185.20`); it was written and syntax-checked but not executed (no SSH, no VPS
  work from this bench). Its rows use `dpi_rule=live`; no profile is involved because there the real censor decides.
- **ICMP carrier not covered** (needs Linux raw sockets/CAP_NET_RAW as well); this bench uses the `tcp` pool carrier
  so the fake-SNI trigger path is the one being classified.
- **iperf3 was not installed**, so `measure.sh`'s optional iperf3 leg produced no `iperf.tsv` rows; the built-in
  `/speedtest` covered both directions.
- Numbers are loopback (0 ms RTT, no loss): they compare modes and rules with each other, not with the real path's
  throughput.

## Files behind these numbers

`testbench/out/` (git-ignored) holds `measured*.csv`, `measure*.log`, per-run `emu-*.log` with the `DPI_READY` rule
list and `DPI_FLOW` verdicts, `flows-*.jsonl`, and the raw `stats-*.json`, `down-*.json`, `up-*.json`.
