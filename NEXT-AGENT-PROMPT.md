# WatTunnel `dev` branch — next agent brief (2.8.0 → next)

You are continuing work on WatTunnel (`github.com/JohnWatsoon/WatTunnel`, branch `dev`, Go 1.26,
static linux/amd64+arm64). Read `CLAUDE.md` first, then `AGENTS.md`. One hard rule up front: every
commit, push, tag and release goes out under the owner's identity only
(`JohnWatsoon <133103370+JohnWatsoon@users.noreply.github.com>`); never add an AI name, trailer or
attribution line anywhere.

## Step 0 — read these files in order (they are the whole context)

1. `CLAUDE.md`, `AGENTS.md` — project rules (wire compatibility, docs sync, ICMP performance pins).
2. `FAKE-SNI-DESIGN.md` — design of the flow-marker feature (2.6.0).
3. `AGENT-HANDOFF-CHANGES.md` — 2.6.0 per-symbol map.
4. `AGENT-HANDOFF-CHANGES-2.md` — 2.7.0 + 2.7.1 per-symbol map, plus its item 8 (refinement
   mission) which is still open.
5. `RESEARCH-2.md` — method research behind 2.7.0/2.7.1 (decision table, verdicts).
6. `RESEARCH-3.md` — field status after the 2026 filter upgrades and what was implemented in 2.8.0.
7. `AGENT-HANDOFF-CHANGES-3.md` — 2.8.0 per-symbol map (the newest code) and the "Not done" queue
   you will work from.
8. `docs/TECHNICAL.md` — every flag/config key/troubleshooting entry (the flag table and the
   Fake-SNI chapter are the parts 2.8.0 touched).

## Step 1 — fully refine everything added on this branch (the standing mission)

The branch carries four feature rounds on top of `main`'s `bf92665` baseline: 2.6.0 (flow marker),
2.7.0 (trigger fix, NAT-follow, auto-TTL, more carriers), 2.7.1 (`sum` mode, probe off-by-one fix,
manager support), 2.8.0 (`pool-rotate` churn, `seqsum` dual marker, checksum-damage fix). Go
through ALL of it end to end with fresh eyes:

- **Code**: `wat/desync.go`, `wat/desync_linux.go`, `wat/desync_other.go`, `wat/desync_test.go`,
  `wat/rotate_test.go`, the churn engine in `wat/carrier_tcp.go` (rotate fields/budget/health-check
  hook), and `cmd/wattun/main.go` (flag wiring). Look for anything the tests don't pin: wrap-around
  arithmetic, the interaction of churn with the slow-connection check and with bonding, error
  paths, the 2 s Wrap timeout story, counter overflow. The 2.8.0 checksum bug was found exactly
  this way (a test flaking ~50 %) — assume there is at least one more latent defect and hunt it.
- **Tests**: keep every pass at full determinism (2.8.0's target suite ran 40 consecutive
  iterations clean; hold that bar). Add what's missing (e.g. churn × keepSlow interaction, clone
  inheritance, `-pool-rotate` config parsing).
- **Consistency**: naming, comments and error strings across the four rounds were written in
  bursts — normalize them (the docs already use "flow marker"/"filter" wording; bring code comments
  in line, keeping flag names and identifiers verbatim).

## Step 2 — rethink how all of it is managed in `wattun-manager`

`wattun-manager` (bash UI) grew its fake-sni support organically (Iran wizard advanced block,
Advanced-settings `k` entry, `--fake-sni/--fake-mode/--fake-ttl` unattended flags; see the 2.7.1
section of handoff 2). Now that `pool-rotate` exists too, redesign the UX so it is one coherent
story instead of scattered asks:

- One "resilience options" block (wizard + Advanced settings + unattended flags in agreement):
  fake-sni name, mode (`seq|ttl|sum|seqsum`), ttl, and `pool-rotate`, with sensible grouped
  defaults and one-line explanations read from `docs/TECHNICAL.md`.
- Consider a named-profile idea: save/recall a working combination (`wattun-manager profile save
  NAME` writes a snippet the wizard can apply), so a user who found a working combination can
  re-apply it in seconds after a reinstall.
- Respect the existing manager conventions (MGR_VERSION unchanged, atomic `mv` on update, `page`
  for every screen, `/stats` as the only live state, `bin_ver_ok` guards for features newer than
  the installed binary). `bash -n wattun-manager` must pass.
- Keep 2.8.0's queue item in mind: expose `pool-rotate` with a `bin_ver_ok 2.8.0` guard.

## Step 3 — only after 1 and 2: pick up new work from the queue

In priority order (details and reasoning in `AGENT-HANDOFF-CHANGES-3.md` "Not done" and
`RESEARCH-3.md` §2):

1. Filter telemetry + auto-mode: a startup probe (SYN with listed/unlisted name, one seq marker,
   one sum marker, one fragmented hello) reporting a per-path profile to `/stats`, from which the
   client picks the marker mode itself. Do NOT implement marker IP-fragmentation unless this probe
   exists first — RESEARCH-3 §3 explains why (a fragmented hello can tag the flow on paths that
   drop fragments; default off, gated).
2. ICMP ceiling governor: learn the per-path rate ceiling from congestion feedback instead of the
   hardcoded default (ramp → signature → back off → cache with hysteresis). Must not touch the
   session/cc hot paths' pinned sim-test behavior.
3. ECH bootstrap ladder: fetch the ECH config through the icmp carrier when DNS-over-HTTPS is
   unavailable, then promote to the fast CDN path.
4. Byte-axis churn (`SetRotate`'s second argument is wired but unexposed) — small.

Whatever you pick: keep every project rule (old/new peers must interoperate — server unchanged and
no new frame types unless ignorable-by-old-peer; client-only where the docs say so; both READMEs in
content sync with native Farsi; benchmark numbers only from real measurements), keep the wording of
all docs and comments in the neutral engineering style already used on this branch, and finish with
`go build ./... && go vet ./...`, the cmd tests, the target suite at 40 clean iterations, and
`bash -n install.sh wattun-manager`. Commit under the owner identity only.

## Environment notes (this Windows box)

- Go needs workspace-local caches: set `GOCACHE=$PWD\.gocache`, `GOMODCACHE=$PWD\.gomodcache`,
  `GOPATH=$PWD\.gopath` before any go command (the shell runs at Low integrity).
- `git commit` from that shell fails on `.git/index.lock`; use one unconfined run for commits.
- Web search/fetch are unavailable in this environment; GitHub API via git's bundled curl with
  `--http1.1` works (`git -c http.sslBackend=openssl clone` also works).
- The full `wat/` suite times out on this box even on clean main (machine-load flakiness); run the
  targeted suites instead, and re-run the full suite on a quiet Linux box with `-timeout 600s`.
- The raw-socket halves (marker injection, real churn recycling) can only be field-validated on a
  Linux box with CAP_NET_RAW (+ CAP_NET_ADMIN for the ISN probe) — flag anything untested-on-
  hardware as such, as every handoff before you did.
