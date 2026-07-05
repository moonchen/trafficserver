# io_uring perf results — TLS A/B, session 2026-07-04

CANONICAL store for the first **TLS-over-io_uring vs TLS-over-epoll** A/B on branch
`io-uring-tls-wip` (HEAD `28c86a0d46`: tls-refactor merge + SSL accepts routed through the
io_uring gate). Same convention as `PERF-RESULTS-2026-06-28.md`: read this file to cite the
numbers, re-measure only for a NEW code change. Raw per-round CSVs live in the bench repo
(`~/work/io-uring-coro-bench/results/tls-*.csv`); the driver is `scripts/measure-tls.sh` there.

## Environment

- Box: i9-12900K, kernel 6.17.0-29-generic. ATS pinned via cgroup-v2 cpuset `atsbench` to
  P-cores 0,2,4,6 (4 ET_NET threads, 1 accept thread); client `wrk2` in `clibench` (cores 8–23);
  governor `performance`, turbo off.
- **Loopback only** (client and ATS on the same box, 127.0.0.1). Prior plain-HTTP work showed
  loopback ≈ parity while a real NIC diverges — do NOT extrapolate these numbers past loopback.
- Binary: `build-rel` (Release, gcc `-O3 -DNDEBUG`, `USE_IOURING=1`, glibc malloc, freelist+pool
  on) installed to `/tmp/ts-iouring-rel`, branch `io-uring-tls-wip` @ `28c86a0d46`, built 2026-07-04.
- TLS: system OpenSSL 3.0.13; negotiated TLSv1.3 `TLS_AES_256_GCM_SHA384`; RSA-2048 self-signed
  cert; session tickets disabled (`proxy.config.ssl.server.session_ticket.enable=0`), no
  resumption — every connection does a full handshake, then HTTP/1.1 keep-alive for the round.
  Each round is a fresh `wrk` process, so each round starts with `conns` full handshakes
  (≈0.4–0.5% of the round's requests; identical in both cells).
- Workload: `wrk2` open-loop fixed rate over **https://**, 100% RAM-cache HIT (validated
  `cache_hit_mem_fresh` == 100% of requests every round), reverse-proxy + remap
  (`map https://perf.test/ http://127.0.0.1:8090/` — nginx origin used for warm-fill only).
- A/B: ONE binary, `proxy.config.net.io_uring.enabled=0|1` in the run's records.yaml — the only
  variable is the net path (epoll `UnixNetVConnection` vs io_uring completion-driven VC; the TLS
  layer above is identical).
- Metric: `cpu/1k` = ATS-cgroup `cpu.stat usage_usec` ÷ requests (gold, per-request efficiency);
  req/s, p50/p99 from wrk2. 6 rounds × 12 s per cell; medians with (min–max). "Fixed rate" is
  the OFFERED (open-loop) rate; both cells achieved ~4% under the 120k small-object offer
  (equally, so the A/B is unaffected) and ~1–2% under the 3.5k large-object offer.

## Harness validation (before any recorded round; hard-fail checks in measure-tls.sh)

- Remap key has no `:port`; startup probe and every round returned only 200s (wrk2 reported
  zero non-2xx/3xx and zero socket errors in all 24 recorded rounds).
- Exact body size per cell verified over TLS (curl: 4096 / 1048576 bytes); wrk bytes/req ≈
  object + ~300 B headers every round.
- TLS actually terminates: `openssl s_client` per cell → `New, TLSv1.3, Cipher is
  TLS_AES_256_GCM_SHA384`.
- **enabled=1 cells really are io_uring**: fresh `diags.log` per run contains both
  `NOTE: io_uring accept enabled for TLS port 8443` and `NOTE: io_uring NetVConnection enabled`
  after the first request; enabled=0 cells verified to contain neither. (Gotcha: these Notes go
  to `diags.log`, NOT the stdout/traffic.out capture.)
- Cache file `truncate`-pre-created; RAM-hit proven per round (`RAM% = 100` in every round).
- Pinning: ATS pid in `atsbench` cgroup, `Cpus_allowed_list=0,2,4,6` across all threads.
- %iowait recorded separately from %idle on the ATS cores each round (below).

## Small object: 4 KB, 600 conns, R=120k req/s fixed (t12, 12 s × 6)

Rate = the plain-HTTP campaign's 120k (≈75% of the TLS saturation ceiling, see probes below).

| cell          | cpu/1k median (min–max)       | req/s median (min–max)    | p50 ms      | p99 ms      |
| ------------- | ----------------------------- | ------------------------- | ----------- | ----------- |
| epoll (=0)    | **0.02275** (0.0226–0.0230)   | 115867 (115094–118031)    | 1.29 (1.23–1.38) | 2.66 (2.44–2.82) |
| io_uring (=1) | **0.02515** (0.0248–0.0254)   | 114756 (113625–116569)    | 1.59 (1.50–1.76) | 3.46 (3.00–3.60) |

**io_uring +10.5% cpu/1k, p50 +0.3 ms, p99 +0.8 ms** at this operating point. Very low
round-to-round variance in both cells.

## Large object: 1 MiB, 200 conns, R=3500 req/s fixed (t8, 12 s × 6)

Rate = ~65% of the *slower* cell's saturation ceiling (io_uring, see probes), so both cells do
identical work (~3.5 GiB/s of TLS records over loopback).

| cell          | cpu/1k median (min–max)       | req/s median (min–max) | p50 ms            | p99 ms           |
| ------------- | ----------------------------- | ---------------------- | ----------------- | ---------------- |
| epoll (=0)    | **0.52715** (0.5163–0.5416)   | 3445.6 (3411–3490)     | 2.10 (1.90–2.40)  | 15.75 (3.67–18.54) |
| io_uring (=1) | **0.54925** (0.5304–0.6866)   | 3467.5 (3375–3490)     | 2.07 (1.91–11.49) | 9.50 (3.43–27.23)  |

**io_uring +4.2% cpu/1k median — but treat this as a soft, wide-CI number.** The io_uring
per-round cost is bimodal: three rounds sit at ≈parity with epoll (0.5304/0.5308/0.5311, low-p99
rounds ~3.4–3.75 ms) and three are elevated (0.5674/0.5682/0.6866, high-p99 rounds ~15–27 ms).
The +4.2% median lands in the gap between the modes; dropping a single elevated round moves it
to ~+0.8%. Contrast the small-object result above, which IS robust (tight, fully-disjoint
cpu/1k ranges). epoll's large-object cpu stays unimodal (0.5163–0.5416) even though its p99 is
similarly bimodal (~3.7 ms vs ~15–19 ms rounds) — the per-round cost split is an io_uring-cell
effect, the p99 bimodality is not. Treat the p99 medians as indicative only.

## Saturation probes (single-round calibration, not 6-round campaign data)

`-R300000` (small) / `-R50000` (large), same configs:

| probe          | epoll (=0)                    | io_uring (=1)                 |
| -------------- | ----------------------------- | ----------------------------- |
| small ceiling  | 159.2k req/s @ cpu/1k 0.0249  | 160.5k req/s @ cpu/1k 0.0248  |
| large ceiling  | 7502 req/s @ cpu/1k 0.5317    | 5365 req/s @ cpu/1k 0.7421    |

Small-object TLS at full CPU saturation is a wash on loopback. Large-object TLS at saturation is
a real gap: io_uring's ceiling is **−28% req/s** (≈5.2 vs 7.3 GiB/s) — consistent with the known
un-coalesced large-transfer weakness from the plain-HTTP NIC campaign. Single rounds; re-run as a
proper campaign before citing beyond "direction and rough size".

## iowait vs idle (recorded per round)

The two cells split their non-busy time very differently: epoll rounds show it as idle (small:
idle ≈ 22–25%, iowait ≈ 8%; large: idle ≈ 40%, iowait ≈ 13%) while io_uring rounds show idle ≈ 0
with iowait ≈ 26–28% (small) / 50–53% (large). The io_uring "iowait" is NOT disk stall — the
workload is 100% RAM-hit with logging off — it is threads parked waiting on ring completions
being charged to iowait. Compare headroom as idle+iowait, which is consistent with the cpu/1k
deltas.

## Conclusions (qualified — loopback only, this box, these operating points)

Under: loopback, OpenSSL 3.0.13/TLSv1.3/AES-256-GCM, Release `-O3`, 4 pinned P-cores no-turbo,
600 conns × 4 KB @ 120k req/s and 200 conns × 1 MiB @ 3.5k req/s, 100% RAM-cache hit, full
handshakes only at round start:

1. **TLS-over-epoll is cheaper per request than TLS-over-io_uring at sub-saturation fixed
   rates**: +10.5% cpu/1k for io_uring on 4 KB objects (robust — tight, fully-disjoint round
   ranges). On 1 MiB the median is +4.2% but the io_uring rounds are bimodal (≈parity vs
   elevated modes), so read it as "somewhere between ~+1% and ~+8%", not a point estimate.
   Both cells are correct (0 errors); this is a cost gap, not a functionality gap.
2. **At CPU saturation, small-object TLS throughput is parity** (≈160k req/s both) — the
   io_uring overhead disappears when the completion path is continuously busy.
3. **Large-object TLS saturation favors epoll substantially** (−28% ceiling for io_uring,
   single-round probe) at these conditions.
4. No unconditional claim either way: prior plain-HTTP results showed loopback and real-NIC
   verdicts diverge (loopback≈parity there, NIC split by object size), and the io_uring
   send-side levers that won on the NIC (send_zc / registered-arena buffers) were NOT enabled
   in this campaign (default config; ciphertext went out through the plain copy write path in
   both cells). Real-NIC TLS and TLS-write ZC/coalescing levers are unmeasured.
