## wattun A/B on emulated link (2026-10-09 23:44:14)

Link: delay 20ms each way, loss 0.2%, rate 100mbit; wattun `wattun 1.3.0`; gost `gost v3.3.0 (go1.26.7 linux/amd64)`; start load 1.12. Median of n rounds.

| contender | n | 1 flow MB/s | 16x2MB MB/s | p50 ms | p95 ms | CPU-s/MB | check |
|---|---|---|---|---|---|---|---|
| direct | 3  | 10.92 | 10.69 | 82.00 | 94.00 | 0.00 | |
| wat-udp | 3  | 10.57 | 10.62 | 43.00 | 81.00 | 0.04 | |
| wat-tcp | 2  | 10.55 | 10.55 | 43.00 | 126.50 | 0.03 | |
| wat-tls | 2  | 10.59 | 10.25 | 43.00 | 108.00 | 0.03 | |
| wat-ws | 2  | 10.59 | 10.61 | 42.50 | 116.50 | 0.03 | |
| gost-tcp | 2  | 10.84 | 10.41 | 83.00 | 95.00 | 0.01 | |
| gost-ws | 2  | 10.76 | 10.40 | 124.00 | 142.50 | 0.01 | |

- skipped bh-tcp / bh-tcpmux (set BH=1 to include; config keys unverified)
- CPU-s/MB counts tunnel processes only (not the python web server or curl); direct has none (0).
