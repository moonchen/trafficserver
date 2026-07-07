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

All three ranges fully disjoint — robust *within this session*. **ioudef −7.0% vs epoll**
(net-path + AIO-backend swap together); **ioutuned −11.7% vs epoll**; lever attribution
**ioutuned −5.1% vs ioudef** (send_zc_fixed + arena `_write_buf` + 256 KiB watermark; AIO
identical). ⚠️ **SUPERSEDED for the tuned/arena cell: the arena cell's level moves ~5%
between SESSIONS (session state, not boot state — the box never rebooted; see the
root-cause subsection at the end of the ladder section) and this session's
0.6228 / −11.7% / −5.1% did not reproduce — cite the ladder's per-lever numbers instead.** The two steps compose
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
   (default) / −11.7% (tuned, ⚠️ that session only — see the ladder section)
   process-cpu/1k.
2. **The WS-B1 levers measured −5.1% on disk-served 1 MiB TLS that session** on top of
   default io_uring, with proven true zero-copy (zc_fixed-only, 0 copied) — at the cost
   of +2.1 ms p50 from ciphertext staging. ⚠️ The ladder section below found the arena
   cell session-state-sensitive and this number non-reproducible. At the 256 KiB
   watermark the robust lever is anonymous send_zc (ladder −11.9% vs epoll without the
   arena); the root-cause subsection's wm=1M pair then shows the arena beating anon
   once staging blocks are 1 MiB (−11.9% vs the wm=1M anon cell) — best measured TLS
   config now = watermark 1M + write_zerocopy + arena, subject to the unexplained ~5%
   arena session swing.
3. Small-object caveat: on a total-system view (process + softirq) the small-object win
   dissolves to ≈ +3% (overlapping ranges); the large-object win survives both views.
4. No throughput claim: every ceiling here is the 1 GbE wire. The loopback −28%
   large-object ceiling gap remains unmeasured on a NIC-bound link; re-test at ≥10 GbE
   before citing any io_uring TLS throughput ceiling.

## TLS lever ladder (BoringSSL, real NIC), session 2026-07-05

The campaign above measured three points; its "ioutuned −5.1% vs ioudef" attributed the
whole lever package (watermark + send_zc + fixed arena) as one step. This ladder isolates
each lever, and reruns EVERY cell interleaved in one session — cross-session variance is
±2%, so mixing rounds from different sessions cannot resolve per-lever deltas of this size.
That discipline turned out to be the finding: the fixed-arena point itself moved ~+5%
across sessions (below).

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
the send_zc_fixed/arena cell's absolute level moves ~5% between SESSIONS while epoll
and ioudef moved <1% between the same two sessions. Config and binary were excluded
in-session; ⚠️ the root-cause subsection below then ruled out boot state entirely (the
box never rebooted between any of these sessions) plus THP, NIC-IRQ affinity, and
IOMMU — the session-state mechanism remains unidentified. Consequence for the campaign
above: its −5.1% "lever package" step should be read as that session's arena point,
not a stable property; the package's robust decomposition in this session is
watermark ~0, anonymous ZC −5.2%, registration +6.4%.

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

### Conclusions (qualified — this box/NIC/client/session, these operating points)

1. In this session, the per-lever decomposition of the large-object win is: io_uring
   net+AIO −7.0%, staging watermark ~0 (enabler only), anonymous send_zc −5.2%,
   buffer registration (send_zc_fixed + arena) **+6.4%** — the best configuration at
   the 256 KiB watermark is watermark + anonymous ZC at **−11.9%** vs epoll, not the
   full package (−6.3%). ⚠️ Superseded as the overall best config: the root-cause
   subsection's wm=1M pair shows watermark 1M + arena beating the wm=1M anon cell by
   −11.9% — best measured TLS config = watermark 1M + write_zerocopy + arena, subject
   to (2).
2. The registered-buffer point is session-state-sensitive (~5% swing between sessions,
   binary and config ruled out in-session; NOT boot state — the box never rebooted,
   see the root-cause subsection); do not cite either session's arena number as a
   stable property. The anonymous-ZC step is the largest single lever measured under
   same-session discipline at wm=256K — noting iouzc's cross-session stability was
   untested here (its same-session disjointness is the evidence; the root-cause
   session later found it stable within global drift), and the session-state mechanism
   is not isolated to buffer registration per se (THP and NIC-IRQ affinity have since
   been ruled out in the root-cause subsection; what remains is unidentified).
3. Small-object: io_uring default −1.4% process-cpu (overlapping ranges — parity-to-
   slight-win), +5.4% on system-total view.
4. Wire-limited: all ceilings are the 1 GbE wire (equal within 0.5% across cells);
   per-request efficiency at fixed ~70%/~76% loads, NO throughput claims.

Raw rows: bench repo `results/tlsnic-ladder-{small,large}.csv` (probe/cal/xt/xp rows
tagged); driver `scripts/campaign-tls-ladder.sh` + extended `scripts/measure-tls-nic.sh`
(per-cell engagement gates, AIO-note gate, TSPREFIX binary-A/B hook), aggregation
`scripts/agg-tls-ladder.py`.

### Why the arena regresses under TLS (root-cause session 2026-07-05)

Root-cause of the iouzc → iouzcfix +6.4% step. Same box/client/method, ONE binary
(`/tmp/ts-bssl-rel` @ `34a8f84525`) for every cell INCLUDING the plain-HTTP control;
every comparison same-session interleaved. Raw rows: bench repo `results/arena-ctl.csv`
(+ `results/arena-smaps.csv`); full evidence log: `.superpowers/sdd/arena-tls-report.md`;
new rig: `scripts/{probe-round.sh,sendtrace.bt,perfstat-round.sh}`.

**Control (plain-HTTP vs TLS, interleaved, one binary).** The 2026-06-28 plain-HTTP
disk-served 1 MiB A/B re-run in the same hours as the TLS pair: plain anon 0.3029 /
fixed **0.2625** (−13.3%, disjoint over 3 passes, instr/req 683K→504K) while TLS iouzc
0.6241 / iouzcfix 0.6210 (parity, overlapping, 3+5 rounds). Registration still wins on
plain HTTP while doing nothing for TLS in the same session → the deficit is
TLS-structural. Two footnotes: (i) the ladder's +6.4% itself did NOT reproduce — today
the arena cell sits at the 07-04 campaign's fast level while epoll/ioudef anchors are
+1.0–1.7% (global drift), i.e. the arena cell ALONE moved ≈ −6% session-relative;
(ii) today's plain-HTTP ABSOLUTE levels sit well above the 06-28 table — anon +40–44%,
fixed +93–99% (the arena's plain win compressed −37% → −13%) — on BOTH the June FP
binary (re-run: 0.2963/0.2543) and the tip binary; box drift across sessions, only
within-session deltas transfer.

**Mechanism (send structure), measured.** `_write` issues ONE `send_zc_fixed` per
CONTIGUOUS registered run and the arena's LIFO free lists hand out non-abutting 256K
blocks, so a run ≈ one block (ZC sends >512K: 4 of 2173); the anon path gathers up to
16 × 32K heap blocks per `sendmsg_zc` (sends cluster at the 512K cap). bpftrace window,
per request:

| per req            | iouzc  | iouzcfix wm=256K | iouzcfix wm=1M |
| ------------------ | ------ | ---------------- | -------------- |
| ZC sends / F_NOTIF | 2.0    | 3.09 (+55%)      | 1.93           |
| plain-copy sends   | 0.9 (~25 KB) | 2.07 (**~185 KB**) | 1.04 (~10 KB) |
| io_uring_enter     | 7.4    | 10.6             | 7.4            |
| arena allocs       | 0      | 9.0              | 3.6            |

Three structural costs at wm=256K: (1) +1.1 ZC sends/req → +1.1 notification CQEs +
enters/task_work, and the coroutine awaits each F_NOTIF before the next send, so more
sends also serialize (p50 +1.2–1.9 ms); (2) broken runs leave ~0.9 tails/req of
128–256K UNDER the 256K ZC threshold re-gate → plain copy sends — **~185 KB/req of
kernel memcpy reintroduced**, the copy the lever exists to remove (anon has no tails:
the gather sends everything staged); (3) staging churn: ~8 × 256K arena allocs/req for
~4.2 blocks of ciphertext (bursts end in partial blocks, freed after drain). Against
that, registration saves the per-send pin — HW counters/req: instr 2252K→2073K (−8%),
cycles −5%, dTLB-misses −27%, but cache-misses +21% — and the two sides cancel: parity.
Under plain HTTP none of this exists (the Doc is ONE contiguous 2M-class block → ~1.4
sends/req, no tails) — registration is pure profit there.

**Causal confirmation.** Raising ONLY `ssl.write_buffer_water_mark` to 1 MiB (staging
blocks = the arena's 1M class) flips the verdict: iouzcfix **0.5400/0.5500** vs iouzc
0.6169/0.6205 interleaved — parity → **−11.9%** (median-vs-median of the wm=1M pair),
sys/1k 0.335→0.17–0.19, p50 IMPROVES
17.1→14.5 ms; the anon cell does not move (its 512K gather cap already binds). The
deficit is entirely send structure; the arena wins under TLS as soon as its sends are
big and few — the same regime as its plain-HTTP win.

**What would make the arena win under TLS**: (a) proven — watermark 1M + arena block
class ≥1M (−11.9% vs the wm=1M anon pair, better p50; costs up to ~1 MiB staged
ciphertext/conn); (b) plausible, unimplemented — gathered registered sends: set
`IORING_RECVSEND_FIXED_BUF` + `buf_index` on a `SENDMSG_ZC` SQE (liburing has no
helper for that combination and kernel support is UNVERIFIED); all arena blocks share
one registered region (buf_index 0), so `_write` could gather non-abutting arena
blocks into one fixed send — would remove the extra notifs AND the copy tails without
(a)'s memory, if the kernel accepts it; (c) ascending-adjacent arena allocation — weaker.
Independently worth fixing: the sub-threshold tail copies (2) and the underfill churn (3).

**The "boot sensitivity" (H3), corrected and narrowed.** The box has not rebooted since
May 23 — every session above shares ONE boot, so the arena swing is SESSION state, not
boot state. Ruled out empirically: THP backing (arena AnonHugePages=0 under madvise AND
always; zone Normal has zero free order-9/10 blocks even after compact_memory — the
arena was 4K-paged in fast and slow sessions alike); NIC IRQ affinity (found reset to
0-23 today — the campaign's 16-23 steering did not persist — and re-steering to 16-23
did not move the arena cell: 0.6173); IOMMU (identity, unchanged); binary/config
(ladder's xp rounds). Fast and slow sessions show IDENTICAL send counts (3.05 ZC/req,
9 allocs/req), so the state scales the PRICE of the arena cell's extra kernel ops, not
their count — consistent with only the notif-heaviest cell swinging. The mechanism of
the ~5% arena-only session swing remains unexplained; treat arena@wm=256K as
parity-with-variance and cite the wm=1M point as its structure-fixed configuration.

## WI-1 / WI-2 / WI-4 campaign — results (2026-07-05)

Executes the three benchmarkable items from `TLS-WRITE-ZC-WORKITEMS.md` (the
send-structure follow-ups to the arena root-cause above). Same box/NIC/client and
gold metric as the ladder; ONE binary throughout except WI-1, which is a
standalone kernel microbench. **All numbers here are workflow-produced.** Decision
for this run: **1 GbE now, 10 GbE later** — the slow-client cells carry the memory
/ backpressure half of WI-4 and are valid on 1 GbE; the fast-client cells approach
the ~940 Mbit wire ceiling, so WI-4's fast-client CPU win is **understated** here
and the definitive fast-client cell is deferred to a 10 GbE pass. cpu/1k only, no
throughput claims.

### WI-1 — gathered registered zero-copy send: **YES (gate passes)**

Standalone sender microbench (modeled on `sender_zc.c`), real NIC atlantic→hawaii,
sink logs received bytes, **n=20000 sends/mode**, sender pinned in the `atsbench`
cgroup (0,2,4,6). liburing 2.15 in a scratch prefix, kernel 6.17. Stages 4×256 KiB
non-adjacent registered arena blocks and sends them via each candidate op vs
today's 4× separate `send_zc_fixed`.

| candidate                                          | kernel result | vs base send_zc_fixed |
| -------------------------------------------------- | ------------- | --------------------- |
| (i) `sendmsg_zc` + `IORING_RECVSEND_FIXED_BUF`     | **ACCEPTED**  | **wins** (below)      |
| (ii) send bundle (`IORING_RECVSEND_BUNDLE`) + fixed | rejected `-95 EOPNOTSUPP` | — |
| (iii) `IORING_SEND_VECTORIZED` + fixed             | rejected `-14 EFAULT` (VECTORIZED+FIXED_BUF combo) | — |

Candidate (i) — `io_uring_prep_sendmsg_zc_fixed`, gathering the run's non-abutting
registered arena blocks (all share `buf_index 0`) into ONE gather+fixed op —
against per-block `send_zc_fixed`:

| per req            | base (per-block) | candidate (i) |
| ------------------ | ---------------- | ------------- |
| sends / req        | 4                | **1**         |
| F_NOTIF / req      | 4                | **1**         |
| io_uring_enter/req | 4                | **1**         |
| cgroup cpu_usec/req | 94.684          | **47.072** (**−50.3%**) |
| zc_copied          | 0 (true ZC)      | 0 (true ZC)   |

Sink independently logged exactly 20,971,520,000 B (= 20000 × 4 × 256 KiB) for
BOTH runs (end-to-end integrity). `zc_copied=0` across all 20000 reqs each — and it
tracked the medium (1 on the loopback prep smoke, 0 on the NIC), so it is not a
stuck zero. Candidates (ii)/(iii) were only proven rejected on loopback (irrelevant
once (i) is the winner).

**Qualification (do not over-read):** WI-1 is a send-path-only microbench, so
−50.3% is the send syscall/notif/completion saving **in isolation** — it will NOT
translate to −50% ATS request cpu/1k (under TLS the AES pass already touches every
byte; ZC only removes the ciphertext→socket copy). The gate criterion (kernel-
accepted AND beats per-block `send_zc_fixed`) is met regardless.

**Consequence:** candidate (i) is exactly the missing branch at
`IOUringNetVConnection.cc:1485-1513`, which today issues `send_zc_fixed` only for a
contiguous registered run and falls back to anonymous `sendmsg_zc` (losing fixed-
buffer registration) for non-adjacent blocks. **WI-3 (`vio.nbytes` block sizing) is
skippable** — the send-structure problem is solved in the op. Follow-on: wire
`io_uring_prep_sendmsg_zc_fixed` into `_write` near `IOUringNetVConnection.cc:1471`,
gathering the arena run's `reg_idx` blocks into one gather+fixed send.

### WI-2 — watermark knee sweep: **knee = 384K** (n=7, 0 failures)

1 MiB disk-served TLS, BoringSSL, NIC, arena ON (`write_zerocopy=1`, threshold
262144, fixed arena on), sweeping `ssl.write_buffer_water_mark`; 6 campaign passes +
1 probe pass, **all cells interleaved same-session** (keeps the ~5% arena session
swing common-mode), **n=7/cell, 0 failures**. Anonymous-ZC (arena off) as the fixed
comparator. Raw: bench repo `results/tlsnic-wm-large.csv`, `tlsnic-wm-probe.csv`.

| watermark | arena cpu/1k median (min–max) | Δ vs 256K |
| --------- | ----------------------------- | --------- |
| 256K      | 0.5919                        | —         |
| 384K      | **0.5131** (0.5091–0.5231)    | **−13.3%** |
| 512K      | ~0.513                        | −13.4% (flat) |
| 768K      | ~0.513                        | −13.3% (flat) |
| 1M        | ~0.508 (0.5042–0.5122)        | −14.1% (flat) |

Arena cpu/1k drops −13.3% from 256K to 384K, then plateaus flat through 512K / 768K
/ 1M (the 384K range 0.5091–0.5231 fully overlaps the 1M range 0.5042–0.5122 — ≥384K
are statistically indistinguishable). The 256K penalty is the copy-tail ballooning
to **112,315 B/req** (vs 3,884–10,068 B/req elsewhere). Anonymous-ZC comparator
stays flat ~0.614–0.620 across the whole sweep. Arena engaged every round
(`zc_fixed>0`, `arena_alloc>0`, `zc_copied==0`; probe rounds: `oversize_fallback=0`,
`class_exhausted=0` — no silent heap fallback).

**Recommend wm=384K.** It captures 95% of the total 256K→1M win (−13.3% of −14.1%);
1M adds only −0.9% (noise). 384K is the smallest watermark that clears the knee — it
rounds up into the arena's 512K size class, so the knee sits at the class boundary.
**This CORRECTS the earlier n=2 "wm=1M −11.9%"**, which mis-attributed the whole
benefit to reaching 1M: with n=7 the win is realized at the 384K knee and 1M buys
nothing extra.

### WI-4 — rate-adaptive staging depth: ~~validated~~ **RETRACTED / REMOVED (2026-07-06)**

> **This section is superseded by
> [`WI-4-ADAPTIVE-STAGING-REMOVED-2026-07-06.md`](WI-4-ADAPTIVE-STAGING-REMOVED-2026-07-06.md).**
> A follow-up investigation on 10 GbE found the rate estimator does not work across
> normal client speeds (it under-reads 4–7×; `S` stays pinned at the 256 KiB cold-start
> from 500 kbit to 1 Gbit), and that deep staging has no benefit regime (flat at 1 MiB,
> *worse* for 8 MiB). The "cpu win" below was produced with a **manual 2 MiB watermark**
> workaround on a pre-check binary — i.e. a de-facto fixed watermark, not adaptation.
> WI-4 has been removed; the TLS write path uses a fixed watermark (default raised to
> 256 KiB). The measurements below are left for the record but should not be relied on.

WI-4 adds `proxy.config.net.io_uring.write_adaptive_depth` (0/1, default off) +
`write_adaptive_tau_ms` (default **50**) and the `proxy.process.net.io_uring.write_adaptive_staged`
counter. The io_uring VC EWMAs a drain-rate `r` from true-ZC F_NOTIF completions (each = the
peer ACKed those pinned bytes, so the completion stream is a drain-rate clock) and exposes a
staging target `S = r × τ`; the SSL encrypt-ahead loop caps `_write_buf` at `S` (in addition to
the static high-water break). Flag-off is a strict no-op. It is a self-tuning replacement for the
static `ssl.write_buffer_water_mark`: shallow staging for slow clients, deep for fast, no knob.

**Method (corrects the first attempt).** An earlier run reported "not validated / gate never
engaged"; that was two harness bugs, not the feature: (a) the workload served **1 MiB** objects but
the arena block is **2 MiB**, so each response fit in ONE block and the depth policy had nothing to
bound — fixed by serving **8 MiB** disk-served objects (object ≫ block → multi-block staging); (b) a
cpuset bug — `setup-box` makes atsbench an *exclusive* partition, carving 0,2,4,6 out of root, so ATS
launched on the leftover HT-siblings and a late cgroup-move stranded some threads (invisible to
`cpu.stat`) — fixed by pinning ATS *before* it spawns threads. Client bandwidth is shaped TLS-only
(HTB on the response flow, never the box's default-route root qdisc). n=3, interleaved same session,
cgroup `cpu.stat` cpu/1k, `zc_copied=0` verified every cell.

**τ sweep (n=3, 8 MiB disk-served TLS, NIC atlantic→hawaii).** cpu/1k and peak `_write_buf`
residency (MB/conn), adaptive at τ∈{10,25,50,75} ms vs the two static references:

| client bw | metric | τ=10 | τ=25 | **τ=50** | τ=75 | static256 | static1m |
|---|---|---|---|---|---|---|---|
| 900 Mbit (fast)† | cpu/1k | 2.82 | 2.58 | **2.38** | 2.43 | 2.86 | 2.46 |
| 900 Mbit | mem MB/conn | 3.25 | 3.94 | 4.88 | 5.25 | 2.56 | 4.50 |
| 400 Mbit | cpu/1k | 4.29 | 3.05 | 2.87 | 2.85 | 3.14 | 2.82 |
| 400 Mbit | mem MB/conn | 3.38 | 3.28 | 3.69 | 3.75 | 2.69 | 3.25 |
| 50 Mbit (slow)* | mem MB/conn | 3.36 | 3.45 | 3.48 | 3.58 | 3.09 | 3.88 |

\* 50 Mbit cpu/1k is noise (≈23 req/window) — memory only. † 900 Mbit is wire-capped on 1 GbE, so
the fast-client cpu win is understated; the definitive fast cell is deferred to a 10 GbE pass.

**Findings.**
1. **Adaptive engages and is true-ZC** — `write_adaptive_staged` > 0 on every NIC cell, `zc_copied=0`
   throughout.
2. **cpu win at speed.** At τ=50, adaptive has the best cpu/1k of the whole matrix at 900 Mbit
   (2.38, beats static1m 2.46 and static256 2.86) and matches static1m at 400 — without an operator
   choosing a watermark. On a wire-capped 1 GbE, so the margin is a floor, not a ceiling.
3. **τ is the tradeoff dial; 50 ms is the knee.** τ < 25 ms over-fragments (τ=10 @ 400 Mbit = 4.29,
   worse than every static, `adstaged`=1350 — tiny sends); τ > 50 ms only adds memory. 50 ms
   maximizes the cpu win at acceptable memory → **new default**.
4. **The slow-client memory win is modest and structurally floored.** Tighter τ does shrink slow-cell
   staging (bw50 mem 3.58→3.36 as τ 75→10, confirming the lever), but it never reaches static256's
   3.09: for a slow client on the ZC path, peak memory is dominated by ciphertext **pinned in-flight
   awaiting the ACK/F_NOTIF**, not by staging depth. `r × τ` has a hard floor there. This tempers
   WI-4's original "shallow staging saves memory for slow clients" ambition.

**Config decisions (committed).** `write_adaptive_tau_ms` default = **50** (swept-optimal).
`write_adaptive_depth` and `ssl.write_buffer_water_mark` are **mutually exclusive** — adaptive depth
self-tunes exactly what the watermark bounds statically, so ATS rejects (`DL_Fatal` at SSL config
load) any config that enables adaptive depth while `ssl.write_buffer_water_mark` is set off-default.

**Verdict.** WI-4 is a self-tuning replacement for `ssl.write_buffer_water_mark`: it matches-or-beats
the best static watermark on cpu/1k with no operator tuning, at τ≈50 ms. Its memory-reduction goal
for slow clients is only weakly realized (ZC-pinning sets the slow-client memory floor). Rig:
`measure-tls-adaptive.sh` (8 MiB workload, TLS-only shaping, pin-before-spawn) + `campaign-tls-adaptive.sh`
+ the τ driver `wi4-tau-sweep.sh`; data in `results/tlsnic-adaptive.csv` and `tlsnic-tau.csv`.

## WI-1 follow-on — gathered registered ZC send wired into `_write` (2026-07-06)

The gate (WI-1 above) proved candidate (i) wins in isolation; this wires it into ATS and
measures it in the full proxy on the NIC.

**Change.** `IOUringNetVConnection::_write`: a registered (arena) run now accumulates every
block sharing `reg_idx` — adjacent or not — instead of breaking at the first non-abutting block.
A contiguous run still issues one `send_zc_fixed`; a **non-adjacent** run issues one
`sendmsg_zc_fixed` over the registered sub-ranges (inlined: `prep_sendmsg_zc` +
`IORING_RECVSEND_FIXED_BUF` in `ioprio` + `buf_index`; the linked liburing 2.4 lacks the combined
helper). New counter `write_zerocopy_gather`; new records toggle
`net.io_uring.write_zerocopy_gather` (default 1, set 0 to restore per-block sends = the A/B
baseline). Gold test `io_uring_tls_write_zc.test.py` gains a deep-staging cell (watermark above
the 2 MiB block) asserting the gather engages, byte-exact, `copied=0`.

**A/B (NIC, BoringSSL Release, hawaii en7 10 GbE — forced + verified per cell).** `deep` cell:
static `write_buffer_water_mark=8 MiB`, 8 MiB disk-served object, 1 GiB→2 MiB arena, 8 conns,
unshaped (fast client), gather ON vs OFF, **6 rounds interleaved**. Rig: `measure-tls-gather.sh`
+ `campaign-gather.sh` + `agg-tls-gather.py`; data `results/tlsnic-gather.csv`.

| median, n=6              | OFF (per-block)   | ON (gather)       | Δ                    |
| ------------------------ | ----------------- | ----------------- | -------------------- |
| sends / req              | 6.582             | 4.694             | **−28.6%** (−28…−30% every round) |
| cpu/1k                   | 7.959 (7.92–8.12) | 7.953 (7.91–8.11) | **−0.24% (flat, noise)** |
| gather ops / fixed sends | 0 / 46602         | 18958 / 32143     | —                    |
| zc_copied (all 12 cells) | 0                 | 0                 | true ZC on the NIC   |

**Read (honest).** The gather engages as designed and removes block-boundary send splits: a deep
buffer of N non-adjacent arena blocks goes out in ~`ceil(bytes / socket_buf)` sends instead of
that plus a split per block boundary (OFF avg 1.28 MB/send, capped by boundaries; ON avg
1.79 MB/send, capped by the ~1.7 MB socket buffer). But **cpu/1k does not move** — confirming the
gate's qualification empirically: under TLS the AES pass dominates, and with *large* blocks (the
correct choice for large-object/fast-client) there are only ~4 blocks/response, so few boundaries
to remove and the socket buffer is already ≈ one block. The spike's 4→1 fold needs *many*
non-adjacent blocks; large blocks deliberately keep the count low. Smaller blocks would give the
gather more to fold but are the wrong design for this workload, so that regime is moot.

**Verdict.** Shipped as a **no-regression cleanup** (−28.6% send syscalls / CQEs / notifs, flat
cpu, `copied=0`), default on. Its durable property is that **block size stops affecting send
count** — a 256 K-block buffer now sends as efficiently as a 2 MiB-block one — which matters for
mixed/adaptive workloads (a slow client wanting small blocks for memory no longer pays a send
penalty), not for the pure large-object/fast-client case where large blocks were already fine.
Not the −50% the isolated spike suggested; that path is already cheap in the full proxy.

**WI-4 interaction (bug found, not fixed here).** The A/B cell is *static* because WI-4 adaptive
cannot deep-stage on the committed binary: `high_water()` binds at `water_mark`, the adaptive path
never raises `water_mark`, and `SSLConfig` rejects `write_adaptive_depth` together with a
non-default `write_buffer_water_mark`. So adaptive runs only at the 64 KiB default watermark, which
caps staging at ~64 KiB (one block) — no deep buffer. WI-4 adaptive as committed does not stage
past 64 KiB; a follow-up is needed (raise the effective staging cap when adaptive is on, or allow a
raised watermark alongside it).
