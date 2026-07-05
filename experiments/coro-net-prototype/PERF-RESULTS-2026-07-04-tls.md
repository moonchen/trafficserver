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

## Why: the small-object gap, root-caused (session 2026-07-04/05)

What is decomposed below is the **steady-state keep-alive gap: +1.93 µs/req (+8.5%)**,
measured clean across interleaved boots (+7–10% per boot pair). The campaign's +10.5%
headline is the same effect at its operating point; the difference is within boot-to-boot
variance (~±2%) plus each campaign round's 600 fresh-connection handshakes (≈0.5% of round
requests, not separately decomposed here).

Method: same binary/box/cell, three cells (epoll; io_uring; io_uring with
`read_provided_buffers=0`), n=3 interleaved boots each. Per boot: a clean HW-counter window
(no tracepoints — tracepoint handlers run in task context and tax the syscall-heavy epoll arm
~1 µs/req if mixed in), a syscall-tracepoint window, two uprobe-count windows (SSL-layer and
event-loop dispatch seams + libssl SSL_read/SSL_write; used only for per-request call counts),
and a filtered SQE-opcode window. Plus one DWARF profile boot per arm (cpu-clock 999 Hz and
PEBS cache-misses, per-request-normalized; sampled totals reconcile with the cgroup gold
metric to 5%). Gap reproduced at +7–10% across boots (campaign's +10.5% included per-round
fresh-connection handshakes). Full evidence log: `.superpowers/sdd/wsA-report.md` (repo),
scripts in `~/work/io-uring-coro-bench` (`evidence-tls.sh`, `probes-tls.sh`, `profile-tls.sh`).

The headline decomposition (means, e1 − e0, per request): **+1.93 µs cgroup (+8.5%)** =
user +1.10 / system +0.82; instructions +4.8k (+4.5%, almost all :u), cycles +6.4k (+9.1%),
cache-references **+42%**, cache-misses **+40%**, dTLB-load-misses **+59%**, IPC 1.50→1.43.
Meanwhile the *dispatch structure is identical*: uprobe counts/req match across arms for
SSLNetVConnection::mainEvent (4.5), transport read/write drives (0.89/1.78), _signal_user
(2.67), SSL_read (2.7), SSL_write (1.8), EThread::schedule_imm (1.9) — and io_uring does
**0.43 syscalls/req vs epoll's 3.69** (which include ~0.95 wasted EAGAIN recvmsg probes/req
that io_uring avoids). SQE mix: 1.96/req = RECV 0.98 + SEND 0.85 + SENDMSG 0.13.

Ranked mechanisms. The ns values close against the profile-measured delta by construction
(+1 186 + 611 + 39 = +1 836 ≈ +1 835 sampled), and the sampled total reconciles with the
cgroup gold metric to ~5% (+1 835 vs +1 926); shares below are of the cgroup +1.93 µs and
sum to 100%:

1. **Same-code locality/IPC degradation — ≈ +1.19 µs/req, ~62% of the gap.** This value is
   the user-total delta minus the (neutral) net-machinery swap — a residual after
   subtraction — but the direct PMU/PEBS spread corroborates it independently: +148 user
   cache-misses/req and the IPC drop land across dozens of unchanged functions (HttpTunnel
   ctor, HttpTransact::State, HdrHeap, IOBufferBlock, allocator, libssl/libcrypto +0.25 µs
   at identical call counts) with no hot spot. Ruled out as drivers: the provided-buffer
   pool (PB-off cell is a wash on cpu, instr AND cache-misses), queue depth (half-rate test:
   user gap persists as in-flight depth halves), SSL dispatch structure (counts identical).
   This is plain-HTTP's A3 residual (cold-line/capacity at rings/frames, LLC+dTLB-walk),
   amplified ~4× because TLS roughly doubles the per-request instruction/data footprint
   (105k vs 58k instr/req) that the added resident state and irq-exit task_work interleaving
   can cool. Fix candidates are weak by prior evidence (frame levers null per the A3
   appendix); the honest statement is that this is the structural cost of the
   completion-driven design at sub-saturation on loopback — it already vanishes at CPU
   saturation (ceiling probes: parity) and the prior plain-HTTP NIC results say the verdict
   flips when syscalls carry real cost.
2. **Kernel path swap at loopback prices — ≈ +0.61 µs/req, ~32%.** Replacing 3.7
   syscalls/req with 1.96 SQE+CQE/req costs MORE kernel time on loopback: io_uring
   completions run as task_work on interrupt-exit (`irqentry_exit_to_user_mode`
   +0.35 µs/req alone), plus per-op fget/apparmor/sock_from_file and `io_submit_sqes`,
   against the cheap saved syscall entries (do_syscall_64/fdget/ep_item_poll/sock_poll all
   ≈ removed). Rate-dependent: at 60k req/s this term is ≈ 0 (epoll amortizes its wakeups
   worse at low load). On the real NIC the same swap measured as a net WIN for plain HTTP
   (prior plain-HTTP NV1: −6% total), so there is nothing to fix for production; it is a
   loopback-pricing artifact. One named, separately fixable subset INSIDE this bucket (not
   additive to it): the unconditional `do_poll(0)` epoll harvest per ring wake — the
   io_uring arm still makes 0.22 epoll_wait/req because `NetHandler::waitForActivity`
   harvests the epoll-only fds (`NetHandler.cc:483`) on EVERY iteration rather than only
   when the poll-bridge CQE fired. Modeled at ~0.07 µs/req (0.22/req × ~300 ns; not
   separately measured). Cheap, real cleanup.
3. **User net-machinery swap — ≈ +0.04 µs/req, ~2% (neutral).** io_uring's own user-side
   machinery (+937 ns: actors, submit paths, signal helpers, liburing) almost exactly
   replaces the epoll machinery it removes (−898 ns: net_read_io, net_write_io,
   load_buffer_and_write, EventIO, libc recv/send/epoll wrappers).
4. Unattributed residual ≈ +0.09 µs (~5%): the profile-vs-cgroup reconciliation slack.
   Boot-to-boot variance (~±2% cpu/1k between boots of the same cell — larger than
   within-boot round variance) bounds how finely the shares should be read.

Also count-neutral (not a cost): on io_uring nearly every request delivers the user
WRITE_COMPLETE via the deferred `_scheduleWriteComplete` dispatch (0.89/req vs 0.03 on epoll,
where the inline sendmsg drains the wbio before the consumer could observe a completing
re-entry) — but it shares the read-drive event slot, so total mainEvent/schedule_imm traffic
is unchanged. Measurement gotchas recorded in the report: `proxy.process.io_uring.submitted`
counts only one submit path (0.84/req vs the tracepoint's true 1.96/req); the
`nh_wait`/`iou_saw` uprobes undercount ~30× (contradicted by syscall callchains) — use
tracepoints for loop rates.

The large-object bimodality was not explained by this campaign (no small-object evidence
transferred; it likely lives in the send-path structure behind the −28% ceiling probe).

## Prod-like NIC campaign (BoringSSL), session 2026-07-04/05

The loopback verdict above does not transfer to a real NIC (its own §"Why" attributes ~32%
of the small-object gap to loopback kernel-path pricing that the plain-HTTP NIC campaign
saw flip to a win). This campaign measures the TLS verdict directly under prod-like
conditions: BoringSSL, a real 1 GbE NIC, a remote client, disk-served large objects, and
the tuned io_uring levers (send_zc_fixed out of the arena-backed SSL `_write_buf`,
WS-B1). Raw CSVs: bench repo `results/tlsnic-{small,large}.csv`; driver
`scripts/measure-tls-nic.sh` + `scripts/campaign-tls-nic.sh` + client-side
`scripts/tlsrate.lua`.

### Environment

- Branch `io-uring-tls-wip` @ `da9b6dc9f5`; ONE binary throughout: `build-bssl-rel`
  (Release gcc `-O3 -DNDEBUG`, `USE_IOURING=ON`, glibc malloc) linked against **BoringSSL**
  shared libs (`~/work/boringssl` @ `b19c870c5`, API version 41; `ldd` shows
  `boringssl-root/lib/libssl.so`), installed to `/tmp/ts-bssl-rel`. Cells differ ONLY in
  records.yaml.
- Server box: i9-12900K, kernel 6.17.0-29-generic, ATS pinned via cgroup cpuset `atsbench`
  to P-cores 0,2,4,6 (4 ET_NET + 1 accept), governor performance, turbo off. NIC atlantic
  1 GbE `enp6s0`, IOMMU group 18 = `identity` (verified), NIC IRQs steered to E-cores
  16–23. nginx origin (warm fill only, loopback :8090) confined to CPUs 1,3,5,7 by the
  cpuset partitions; idle during every measurement window (0 misses in-window).
- Client: hawaii (M1 Mac Mini, 8 cores) over the 1 GbE link, wrk 4.2.0 (kqueue, links
  openssl@4), `ulimit -n 8192` (macOS default 256 silently drops 5 of 256 conns). wrk 4.x
  has no `-R`, so fixed rates are closed-loop delay-shaped (`tlsrate.lua delay()`),
  calibrated once per workload and IDENTICAL across cells; achieved rates matched across
  cells (small 18.4–18.5k, large 78.2–79.0 — one ioudef round hit 15.9k, a client-side
  blip; its cpu/1k is per-request and in-family). Client headroom during rounds: ≥80% idle.
- TLS: TLSv1.3 `TLS_AES_256_GCM_SHA384` (verified from hawaii per boot), RSA-2048
  self-signed, session tickets off, HTTP/1.1 keep-alive. Measurement is an in-window
  sample (8 s into the wrk run, 12 s window): steady-state keep-alive, handshake ramp
  excluded (unlike the loopback tables above, which include round-start handshakes).
- Metric: cpu/1k = ATS-cgroup `usage_usec`/req (gold, same as loopback). Global softirq
  s/1k recorded separately (NIC rx/tx completion work lands on the E-cores, off the ATS
  cgroup). %iowait/%idle from the ATS cores per round.
- 1 GbE bounds everything: ceilings probed per cell first (closed loop), all six ceilings
  are line-rate-equal, rounds then ran at ~70% of the slower ceiling. This is a
  per-request efficiency A/B at fixed offered load, NOT a throughput comparison — the
  −28% loopback ceiling gap has no NIC counterpart to measure at 1 GbE (both cells idle
  waiting for the wire).

### Cells

| cell     | records delta vs common                                                                                  |
| -------- | -------------------------------------------------------------------------------------------------------- |
| epoll    | `net.io_uring.enabled=0`, `aio.mode=thread` (prod-like master baseline; ssl watermark default)            |
| ioudef   | `enabled=1`, everything else default (aio auto → **io_uring AIO**, verified "Using io_uring for AIO" Note) |
| ioutuned | `enabled=1, write_zerocopy=1, write_zerocopy_threshold=262144, fixed_arena_size=1GiB, fixed_arena_block_size=2MiB` + `ssl.write_buffer_water_mark=262144` + `aio.mode=io_uring` |

Note the epoll baseline sets `aio.mode=thread` explicitly: with the default `auto` this
build would run io_uring AIO under an epoll net path, which is not a prod baseline (prod
epoll builds run thread AIO). Consequence: in the LARGE cell, ioudef−epoll conflates the
net-path swap with the AIO-backend swap; ioutuned−ioudef is a clean lever attribution
(both use io_uring AIO). In the SMALL cell (RAM-hit, zero in-window disk I/O) all deltas
are pure net-path.

### Validation (hard-fail per boot/round, all 36 recorded rounds passed)

200 + exact body size over TLS from hawaii; TLSv1.3 s_client probe from hawaii; io_uring
accept-for-TLS-port + NetVConnection Notes in diags.log iff enabled=1; Cpus_allowed_list
0,2,4,6; small = 100% `cache_hit_mem_fresh`; large = disk-served proven per round by
`cache.pread_count`/req ≈ 100% + `hit_fresh` ≈ 100% + mem-serves ≈ 0% (rotation widened to
200×1 MiB objects after the initial 50-object config showed 0–22% phase-dependent serves
from the cache's single-doc last-open-read lookaside — 64 in-flight conns over 50 objects
always hold duplicates); tuned large = `write_zerocopy_fixed>0` AND `write_zerocopy_copied==0`
in-window AND arena allocs >0; zero Non-2xx and zero timeouts everywhere.

### Ceiling probes (closed loop, single rounds)

small: epoll 26 106, ioudef 26 109, ioutuned 26 108 req/s — identical, wire-bound
(≈115 MB/s with headers), ATS cores ≈86% non-busy in every cell. large: epoll 112.2,
ioudef 113.2, ioutuned 112.1 req/s — identical, wire-bound. Rounds: small R≈18.4k
(delay 12 ms), large R≈78.4 (delay 750 ms).

### Small object: 4 KB RAM-hit, 256 conns, ~18.4k req/s (12 s × 6, interleaved boots)

| cell     | cpu/1k median (min–max)      | user/sys /1k    | p50 ms | p99 ms | softirq s/1k med |
| -------- | ---------------------------- | --------------- | ------ | ------ | ---------------- |
| epoll    | **0.02175** (0.0209–0.0220)  | 0.0167 / 0.0051 | 1.25   | 3.06   | 0.0080           |
| ioudef   | **0.02095** (0.0208–0.0211)  | 0.0154 / 0.0055 | 1.29   | 3.13   | 0.0097           |
| ioutuned | **0.02105** (0.0209–0.0212)  | 0.0146 / 0.0065 | 1.29   | 3.12   | 0.0092           |

io_uring −3.7% (default) / −3.2% (tuned) process-cpu/1k vs epoll; tuned≈default (+0.5%,
noise) — the ZC/arena levers are moot for 4 KB sends (threshold 256 KiB; zc=0 all rounds),
as expected. The epoll range overlaps the io_uring cells at its best round (0.0209; the
other five ≥0.0216), so this is a modest, mostly-consistent win, not a disjoint-range one.
p50 +0.04 ms for io_uring. Contrast loopback: **+10.5% → −3.7%**, i.e. the small-object
verdict flips on a real NIC exactly as the "Why" section's loopback-pricing term (and
plain-HTTP NV1, −6%) predicted.

**System-view caveat**: counting global softirq alongside process cpu, small flips to
io_uring +3.0% (default; ranges overlap) — io_uring's small-object rounds carry ~+0.0017
softirq s/1k that epoll does in syscall context instead. On the process/cgroup gold
metric (what the prior campaigns cite) io_uring wins; on total-system cost small-object
TLS at this operating point is ≈ parity-to-slightly-behind. Large is a win on BOTH views
(process −11.7%, system-total −12.0%, tuned).

### Large object: 1 MiB disk-served, 64 conns, ~78.4 req/s (12 s × 6, interleaved boots)

| cell     | cpu/1k median (min–max)      | user/sys /1k    | p50 ms | p99 ms | softirq s/1k med |
| -------- | ---------------------------- | --------------- | ------ | ------ | ---------------- |
| epoll    | **0.70535** (0.6925–0.7082)  | 0.3158 / 0.3873 | 13.93  | 486.6  | 0.0423           |
| ioudef   | **0.65595** (0.6520–0.6595)  | 0.2994 / 0.3541 | 13.98  | 494.1  | 0.0425           |
| ioutuned | **0.62280** (0.6164–0.6317)  | 0.3239 / 0.3005 | 16.11  | 494.6  | 0.0319           |

All three ranges fully disjoint — robust *within this boot*. **ioudef −7.0% vs epoll**
(net-path + AIO-backend swap together); **ioutuned −11.7% vs epoll**; lever attribution
**ioutuned −5.1% vs ioudef** (send_zc_fixed + arena `_write_buf` + 256 KiB watermark; AIO
identical). ⚠️ **SUPERSEDED for the tuned/arena cell: the ladder section below shows the
arena cell is boot-sensitive (~5%) and this boot's 0.6228 / −11.7% / −5.1% did not
reproduce — cite the ladder's per-lever numbers instead.** The two steps compose
multiplicatively: 0.930 × 0.949 = 0.883 ≈ the −11.7% total. The loopback
large-object bimodality did NOT reappear: io_uring rounds are tight (spread ≤1.2% of
median in ioudef). Tuned costs +2.1 ms p50 (256 KiB ciphertext staging before first send)
— an efficiency/latency trade to name when enabling the watermark. ZC engagement across
the six tuned rounds: 17 245 zerocopy sends, **17 244 send_zc_fixed, 0 copied** (~3.05
sends/req at ~350 KB/send), arena allocs ~8 450/round — true zero-copy on the NIC, no
kernel copy-back, every ZC send took the registered-buffer path.

### Conclusions (qualified — this box/NIC/client, these operating points)

Under: 1 GbE atlantic NIC (wire-bound ceilings), BoringSSL TLSv1.3 AES-256-GCM RSA-2048
tickets-off keep-alive, Release -O3, 4 pinned P-cores no-turbo, NIC IRQs on E-cores,
256 conns × 4 KB RAM-hit @ ~18.4k req/s and 64 conns × 1 MiB disk-served @ ~78 req/s
(both ≈70% of line rate), steady-state windows excluding handshake ramp:

1. **TLS-over-io_uring is cheaper per request than TLS-over-epoll on the real NIC at
   these operating points** — the loopback verdict inverts, matching the plain-HTTP
   precedent (NV1): small −3.7% (default levers; tuned moot at 4 KB), large −7.0%
   (default) / −11.7% (tuned, ⚠️ this boot only — see the ladder section)
   process-cpu/1k.
2. **The WS-B1 levers measured −5.1% on disk-served 1 MiB TLS this boot** on top of
   default io_uring, with proven true zero-copy (zc_fixed-only, 0 copied) — at the cost
   of +2.1 ms p50 from ciphertext staging. ⚠️ The ladder section below found the arena
   cell boot-sensitive and this number non-reproducible; the robust lever is anonymous
   send_zc (ladder −11.9% vs epoll without the arena).
3. Small-object caveat: on a total-system view (process + softirq) the small-object win
   dissolves to ≈ +3% (overlapping ranges); the large-object win survives both views.
4. No throughput claim: every ceiling here is the 1 GbE wire. The loopback −28%
   large-object ceiling gap remains unmeasured on a NIC-bound link; re-test at ≥10 GbE
   before citing any io_uring TLS throughput ceiling.

## TLS lever ladder (BoringSSL, real NIC), session 2026-07-05

The campaign above measured three points; its "ioutuned −5.1% vs ioudef" attributed the
whole lever package (watermark + send_zc + fixed arena) as one step. This ladder isolates
each lever, and reruns EVERY cell interleaved in one session — cross-boot variance is
±2%, so mixing rounds from different boots cannot resolve per-lever deltas of this size.
That discipline turned out to be the finding: the fixed-arena point itself moved ~+5%
across boots (below).

### Conditions

- ONE binary throughout: branch `io-uring-tls-wip` @ `34a8f84525` (2 commits past the
  campaign above: docs + thread-exit destructors for the read buf ring/frame pool — no
  steady-state path change), `build-bssl-rel` Release, BoringSSL @ `b19c870c5`, installed
  /tmp/ts-bssl-rel (binary md5 ed9161a7ddca39b51c8ad6b7cac1b6f1). Cells differ ONLY in
  records.yaml. Same box/client/method as the campaign above (i9-12900K pinned 0,2,4,6,
  no-turbo, atlantic 1 GbE, IOMMU group 18 identity, NIC IRQs on E-cores 16–23, wrk on
  hawaii, 12 s in-window samples, 6 passes with all 7 cells interleaved per pass; 42/42
  rounds passed the hard-fail validation, zero Non-2xx/timeouts).
- Fresh ceiling probes this session: small 26 114 / 26 114; large 111.9 / 112.2 / 112.0 /
  112.3 / 111.7 req/s (epoll/ioudef/iouwm/iouzc/iouzcfix) — all wire-bound, equal within
  0.5%. Large rounds: delay 750 ms → 78.2–78.8 req/s ≈ 70% of ceiling. Small rounds:
  wrk's delay() is integer-ms, and 11 ms (closest to 70%) settled at ~19.9k ≈ 76% of
  ceiling in steady state (the cal round read 17.7k; the closed loop crept up) — delays
  IDENTICAL across cells, so the A/B is unaffected; two client-side rate blips (17.5k,
  18.8k) left in, cpu/1k is per-request and in-family.
- AIO is asserted per boot from diags ("Using thread for AIO" in epoll, "Using io_uring
  for AIO" in every iou cell — aio left `auto` there, proven not assumed). The
  epoll→ioudef step therefore still conflates the net-path swap with the AIO-backend
  swap on this disk-served workload; every later step holds AIO fixed.

### Cells (each = previous + ONE change)

| cell     | delta vs previous                                                        |
| -------- | ------------------------------------------------------------------------ |
| epoll    | `enabled=0`, `aio.mode=thread` (prod-like baseline)                       |
| ioudef   | `enabled=1`, all levers default                                           |
| iouwm    | + `ssl.write_buffer_water_mark=262144` (bigger ciphertext staging only)   |
| iouzc    | + `write_zerocopy=1, threshold=262144`, arena OFF (anonymous send_zc)     |
| iouzcfix | + `fixed_arena_size=1GiB, block=2MiB` (send_zc_fixed; = prior "ioutuned") |

### Large: 1 MiB disk-served, 64 conns, ~78.4 req/s (12 s × 6, interleaved)

| cell     | cpu/1k median (min–max)     | Δ vs prev | Δ vs epoll | user/sys /1k    | p50 ms | p99 ms | softirq s/1k |
| -------- | --------------------------- | --------- | ---------- | --------------- | ------ | ------ | ------------ |
| epoll    | **0.69830** (0.6931–0.7052) | —         | —          | 0.3183 / 0.3780 | 14.49  | 493.7  | 0.0318       |
| ioudef   | **0.64970** (0.6481–0.6561) | −7.0%     | −7.0%      | 0.2930 / 0.3591 | 13.71  | 485.7  | 0.0319       |
| iouwm    | **0.64910** (0.6405–0.6546) | −0.1%     | −7.0%      | 0.3087 / 0.3388 | 14.14  | 487.1  | 0.0318       |
| iouzc    | **0.61510** (0.6082–0.6211) | −5.2%     | −11.9%     | 0.3387 / 0.2734 | 15.88  | 493.9  | 0.0373       |
| iouzcfix | **0.65455** (0.6514–0.6564) | +6.4%     | −6.3%      | 0.3416 / 0.3115 | 17.14  | 490.6  | 0.0319       |

Steps compose multiplicatively: 0.9304 × 0.9991 × 0.9476 = 0.8809 (iouzc's −11.9%) and
× 1.0641 = 0.9374 (iouzcfix's −6.3%). Range structure per step:

- **epoll → ioudef −7.0%**: disjoint ranges; replicates the campaign above (−7.0%).
  Net-path + AIO-backend conflated (see Conditions).
- **ioudef → iouwm ~0**: ranges overlap almost completely — the 256 KiB ciphertext
  staging watermark alone buys nothing measurable here. Its role is enabling: without
  it, TLS sends stay at ~16 KiB records, below the 256 KiB ZC threshold, and the ZC
  levers never engage. Costs nothing either (+0.4 ms p50, in-noise).
- **iouwm → iouzc −5.2%**: fully disjoint below every other io_uring cell — anonymous
  send_zc on the staged ciphertext is THE lever that pays. All of it is system-time
  (sys 0.3388→0.2734/1k, the copy leaving the kernel path); +1.7 ms p50 and +0.0055
  softirq s/1k move against it (ZC notification work), and it still wins on the
  system-total view (0.65340 vs epoll 0.73300, −10.9%).
- **iouzc → iouzcfix +6.4%**: disjoint above iouzc, landing back at the ioudef/iouwm
  level (its range overlaps ioudef's — vs ioudef it is parity, +0.7%). In THIS session
  the fixed-arena/registered-buffer lever undoes most of the anonymous-ZC win.

### The iouzcfix point vs the campaign above (cross-session shift, binary ruled out)

The prior session's equivalent cell (ioutuned) measured **0.62280** — today the same
configuration measures ~0.652 no matter how it is asked: iouzcfix 0.65455 (×6), literal
`ioutuned` records including its explicit `aio.mode=io_uring` 0.6492/0.6529 (tags
xt1–2), and — the decisive test — the prior campaign's own source (`da9b6dc9f5`, fresh
worktree build, same flags/BoringSSL) interleaved against the tip binary in this same
session: prior binary 0.6465/0.6579 (xp1–2) vs tip 0.6643/0.6513 (xt3–4). Overlapping,
both at today's level. So: not the 2-commit code delta, not the aio-mode nuance —
the send_zc_fixed/arena cell's absolute level is boot-sensitive by ~5% while epoll and
ioudef moved <1% between the same two boots. Cause not identified; after config and
binary were excluded in-session, boot-level state interacting with the
registered-buffer path is what remains (IOMMU group read `identity` both sessions).
Consequence for the campaign above: its −5.1% "lever package" step should be read as
that boot's arena point, not a stable property; the package's robust decomposition on
today's boot is watermark ~0, anonymous ZC −5.2%, registration +6.4%.

Mechanism observation (recorded, not causal): the arena-backed `_write_buf` issues
~3.05 sends/req (~350 KB) vs ~2.0 sends/req (~512 KB) for the malloc-backed staging
buffer — 50% more, smaller sends on the fixed path. The prior session showed the same
3.05 sends/req at its faster level, so send count alone does not explain the shift.

### Small: 4 KB RAM-hit, 256 conns, ~19.9k req/s (12 s × 6, interleaved)

| cell   | cpu/1k median (min–max)     | Δ vs epoll | user/sys /1k    | p50 ms | p99 ms | softirq s/1k |
| ------ | --------------------------- | ---------- | --------------- | ------ | ------ | ------------ |
| epoll  | **0.02095** (0.0206–0.0215) | —          | 0.0146 / 0.0060 | 1.28   | 3.08   | 0.0079       |
| ioudef | **0.02065** (0.0203–0.0213) | −1.4%      | 0.0142 / 0.0066 | 1.34   | 3.11   | 0.0100       |

Ranges overlap heavily: −1.4% is parity-to-slight-win, weaker than the prior session's
−3.7% (same direction; both sessions' small deltas are within each other's overlap
structure). On the system-total view (process + softirq) it flips to +5.4% io_uring,
same caveat as the campaign above. The ZC/arena levers are not re-measured at 4 KB —
the campaign above already established them moot there (threshold 256 KiB, zc=0 all
rounds, tuned ≈ default +0.5%).

### Engagement evidence (hard-fail gates, all 42 rounds + 6 xt/xp rounds green)

- iouwm: `write_zerocopy`=0 and `write_zerocopy_fixed`=0 every round (watermark only).
- iouzc: 11 252 anonymous ZC sends across 6 rounds (~2.0/req), **fixed=0, copied=0** —
  true anonymous zero-copy on the NIC, no kernel copy-back, no registered path.
- iouzcfix: 17 201 ZC / 17 208 fixed (±edge-of-window sampling), **copied=0**, arena
  allocs ~8 480/round — every ZC send took the registered-buffer path.
- Per boot: AIO-backend Note asserted; disk-serving proven (pread/req ≈100%, ram 0.0%,
  hit ≈100%); small 100% mem-fresh; TLSv1.3 from hawaii; pinning 0,2,4,6.

### Conclusions (qualified — this box/NIC/client/boot, these operating points)

1. On today's boot, the per-lever decomposition of the large-object win is: io_uring
   net+AIO −7.0%, staging watermark ~0 (enabler only), anonymous send_zc −5.2%,
   buffer registration (send_zc_fixed + arena) **+6.4%** — the best configuration this
   session is watermark + anonymous ZC at **−11.9%** vs epoll, not the full package
   (−6.3%).
2. The registered-buffer point is boot-sensitive (~5% swing across two boots, binary
   and config ruled out in-session); do not cite either session's arena number as a
   stable property. The anonymous-ZC step is the largest single lever measured under
   same-session discipline — noting iouzc itself has no cross-boot measurement yet, so
   its boot-stability is untested (its same-session disjointness is the evidence), and
   the boot-sensitivity mechanism is not isolated to buffer registration per se
   (registration vs DMA/IOMMU boot state vs other per-boot layout effects remain
   candidates).
3. Small-object: io_uring default −1.4% process-cpu (overlapping ranges — parity-to-
   slight-win), +5.4% on system-total view.
4. Wire-limited: all ceilings are the 1 GbE wire (equal within 0.5% across cells);
   per-request efficiency at fixed ~70%/~76% loads, NO throughput claims.

Raw rows: bench repo `results/tlsnic-ladder-{small,large}.csv` (probe/cal/xt/xp rows
tagged); driver `scripts/campaign-tls-ladder.sh` + extended `scripts/measure-tls-nic.sh`
(per-cell engagement gates, AIO-note gate, TSPREFIX binary-A/B hook), aggregation
`scripts/agg-tls-ladder.py`.
