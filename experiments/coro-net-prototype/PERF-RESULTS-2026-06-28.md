# io_uring perf results — session 2026-06-28

CANONICAL store for the io_uring net-path + registered-arena A/B measurements, so the numbers survive
and any agent can show the progression WITHOUT re-running (the bench repo `findings/*.txt` get
overwritten each run; re-running needs the pinned box + the `hawaii` second host). Future sessions:
append new dated sections / files here. To SHOW the step ladder, read this file; only re-measure for a
NEW code change.

## Environment

- Box: ATS pinned via cgroup `atsbench` to P-cores 0,2,4,6; governor `performance`, turbo off.
- NIC: atlantic 1 GbE (`enp6s0`, 192.168.1.165) under `iommu=pt` (NIC in `identity` domain).
- Client: `wrk` on a second host `hawaii` (192.168.1.220, M1 Mac) — a real second host is REQUIRED;
  localhost is loopback and `send_zc` always copy-falls-back there.
- Origin: nginx on the ATS box (127.0.0.1:8090), 1 MiB objects `/L1m/0..49.bin`, Host `perf.test`.
- Binary: `build-fp` (frame pointers) installed to `/tmp/ts-iou-fp`, branch `io-uring-coroutine-wip`.
- Metric: `cpu/1k` = CPU-seconds per 1000 requests (cgroup `usage_usec` delta / req); `instr/req` from
  `perf stat`. Medians over 3 interleaved reps (interleave to control thermal drift; trust deltas, not
  absolutes — absolutes drift run-to-run). `zc_copied=0` == genuine zero-copy on the NIC.

## Headline: master → best (same disk-served 1 MiB test, same matrix)

`measure-fixed-ab.sh epoll|fixed` — disk-served 1 MiB cache hits (small RAM cache + round-robin over 50
objects forces disk reads -> the arena Doc path). `epoll` = `io_uring.enabled=0` (the stock
UnixNetVConnection path master uses); `fixed` = io_uring + size-class arena + `send_zc_fixed`.

| mode                             | cpu/1k    | instr/req | zc_fixed | zc_copied |
| -------------------------------- | --------- | --------- | -------- | --------- |
| **master** (epoll + thread-AIO)  | **0.341** | 680K      | 0        | 0         |
| **best** (io_uring + arena + ZC) | **0.132** | 361K      | ~1.4/req | **0**     |

**-61% cpu/1k (~2.6x requests per CPU-second), true zero-copy on the NIC.** From the disk-cache step
ladder below, verified 100% disk reads (ram_cache.hits=0). (Supersedes an earlier -44% number that used
auto-AIO -- not a true thread-AIO master -- and a 256 MB arena whose 2M class exhausted at 48 conns,
diluting the fixed step. Same scenario, measured properly.)

## Disk-cache serving step ladder (1 MiB objects, 100% disk reads)

`measure-fixed-ab.sh epoll|copy|anon|fixed` x3 interleaved -- disk-served 1 MiB cache hits (small RAM
cache + round-robin over 50 objects forces disk reads). VERIFIED disk-heavy: ram_cache.hits=0,
bytes_used=0 (a 1 MiB object does not fit the 512 KB RAM cache), cache.read.success=every request,
read_busy=0 (no read sharing). `aio.mode` is `thread` for the master and `io_uring` for the rest; the
arena is 1 GiB so its 2M class (~85 blocks) does not exhaust at 48 conns (a 256 MB arena did, diluting
the fixed step to ~0.78 fixed sends/req). Each row adds one layer.

| step                              | what it adds                                   | cpu/1k    | step Δ | vs master | instr/req |
| --------------------------------- | ---------------------------------------------- | --------- | ------ | --------- | --------- |
| 1. epoll + thread-AIO (master)    | epoll net, AIO-thread disk read, copy send     | **0.341** | —      | —         | 680K      |
| 2. + io_uring (net + AIO)         | io_uring net AND io_uring disk read, copy send | **0.315** | -7.7%  | -7.7%     | 641K      |
| 3. + zero-copy send (anon)        | no send memcpy (pages pinned per send)         | **0.211** | -33%   | -38%      | 679K      |
| 4. + fixed buffer (send_zc_fixed) | disk read into the registered arena, no pin    | **0.132** | -37%   | **-61%**  | 361K      |

reps: epoll 0.3409/0.3458/0.3375, copy 0.3162/0.3147/0.3033, anon 0.188/0.211/0.218, fixed
0.1322/0.1381/0.1304 (very low variance). zc_copied=0 throughout the ZC steps; fixed zc_FIXED ~= zc_total
(full arena engagement, ~1.4 fixed sends/req).

Shape: io_uring (net + AIO) is a modest -7.7% on large objects. Zero-copy send is the big leap (-38%
cumulative): removing the 1 MiB memcpy -- note instr/req barely moves (641K->679K), the win is pure
memory bandwidth (pinning costs instructions but saves the copy's cache traffic). Fixed buffer is the
cleanest step here (-61% cumulative): the disk Doc is read STRAIGHT into the registered arena block, so
the send skips BOTH the copy AND the per-send pin -> instr/req collapses to 361K (-44% vs copy).
Disk-cache serving is the arena's best case: the whole object is one big contiguous registered block,
read once and DMA'd to the NIC with zero copies and zero per-send setup.

### ZC disk read (read_fixed) -- INVESTIGATED, NO-GO (profile)

Idea: io_uring_prep_read_fixed for the cache disk read into the already-registered arena block (the
read-side mirror of send_zc_fixed) -> fully-registered round trip. FEASIBLE: the io_uring AIO read uses
IOUringContext::local_context() (AIO.cc:607), the same per-thread ring the arena registers on, so
read_fixed could address it by buf_index 0. But profiling the fixed step's read path (perf -C 0,2,4,6 -g
under load) shows it is NOT worth it: the cache opens O_DIRECT (DIO path confirmed: __iomap_dio_rw /
btrfs_dio_iomap_begin / __submit_bio), so the read already DMAs disk->buffer with NO copy. The only thing
read_fixed removes is the per-IO buffer PINNING (`__iov_iter_get_pages_alloc`), which is ~0.07% of samples
-- on par with cache bookkeeping (CacheVC::handleReadDone), i.e. negligible. (Contrast: the send-side
anon->fixed -37% step was the whole send_zc machinery -- pinning + notification + skb-zerocopy setup --
far more than a bare get_user_pages.) So O_DIRECT already captured the read win; read_fixed adds ~nothing.
NOTE the workload is NIC-bound at 1 GbE (cores mostly idle), so CPU isn't even the bottleneck here.
VERDICT: do not build ZC disk read; the disk-serve win is maximized by send_zc_fixed. (Would only matter
on BUFFERED storage -- a non-O_DIRECT fs/tmpfs -- where the read copies; not the prod case.)

## Pass-through send-ZC via recv coalescing (T3.4)

NOTE the name: the recv is NOT zero-copy (it still copies kernel->buffer). This COALESCES the origin
recv into a large registered buffer so the pass-through SEND to the client clears the threshold and can
use `send_zc_fixed`. Config: `net.io_uring.recv_coalesce` (+ `recv_coalesce_size`).

`measure-recvzc-ab.sh copy|recvzc` — cache OFF, every request is an origin->client tunnel. wrk over the
NIC -> ATS -> nginx (loopback). `recvzc` coalesces the origin recv (SO_RCVLOWAT=256K + POLL_FIRST) into
arena blocks -> the client send is `send_zc_fixed`. Needs `net.core.rmem_max` raised to 4M so
SO_RCVLOWAT reaches 256K.

| mode                | cpu/1k     | instr/req | zc_fixed | zc_copied |
| ------------------- | ---------- | --------- | -------- | --------- |
| copy (pass-through) | 0.511      | 1.08M     | 0        | 0         |
| **recvzc**          | **0.368**  | 0.59M     | ~8100    | **0**     |

**-28% cpu/1k, -45% instr/req, true zero-copy on the NIC.** The send-side memcpy removal far outweighs
the POLL_FIRST/coalesce overhead. (Pass-through copy is pricier than disk copy because it copies BOTH
the 1 MiB recv AND send; recv-ZC strips the send copy.) reps (clean): recvzc 0.368/0.370, one outlier
0.579 with 66 wrk timeouts.

### Minimal-lowat sweep -> GO/NO-GO (the win needs a big, prod-unsafe lowat)

`measure-recvzc-ab.sh recvzc 48 18 <rep> <recv_coalesce_size>` -- the coalesce size IS the send size, so
it sweeps the send_zc crossover. 3 reps each, vs the same copy baseline (cpu/1k 0.501):

| coalesce (= SO_RCVLOWAT) | cpu/1k | vs copy   | instr/req | send_zc/req |
| ------------------------ | ------ | --------- | --------- | ----------- |
| copy (baseline)          | 0.501  | —         | 1078K     | 0           |
| recvzc 256K              | 0.365  | **-27%**  | 592K      | 4           |
| recvzc 128K              | 0.450  | **-10%**  | 887K      | 8           |
| recvzc 64K               | 0.577  | **+15%**  | 1307K     | 16          |

The win scales with the send size because send_zc's per-send notification (F_NOTIF) roundtrip only
amortizes over LARGE sends: 256K -> 4 sends/req (-27%); 128K -> 8 sends (-10%, marginal); 64K -> 16
sends (+15%, LOSES -- per-send overhead > the memcpy it saves). So a NET win needs >= ~128K coalesce
(really 256K), i.e. a HIGH SO_RCVLOWAT.

**VERDICT: NO-GO for general production.** The win only exists at a high lowat (>=128K), which is exactly
what's UNSAFE for TLS/H2 (the next-step byte count is unpredictable -> a high lowat stalls). And for H2
it's moot regardless: `Http2DataFrame::write_to` (Http2Frame.cc) memcpy's the body into the H2 OUTPUT
buffer during framing ("...to reduce SSL_write() calls"), so the bytes the NIC DMAs are a fresh copy, not
the arena recv block -- arena-backing the recv buffer is wasted under H2. recv-coalesce-ZC is therefore a
NICHE optimization: plain-HTTP/1.1 large-object pass-through with known-large Content-Length where a high
lowat is acceptable. Keep it OFF by default (it is); do not invest further. The general win is the
disk-served send-ZC arena (-44%) above.

CAVEAT: recvzc also shows MORE wrk timeouts at 256K (16/42/66 vs copy 13) = coalesce latency.

## `SO_RCVLOWAT` + io_uring recv spike (scratchpad/rcvlowat_spike.c)

io_uring recv honors `SO_RCVLOWAT` ONLY with `IORING_RECVSEND_POLL_FIRST` (a per-SQE flag) -- without it
the inline non-blocking recv ignores rcvlowat under load (first cqe = one 8K chunk). With it, every
completion is a coalesced >= rcvlowat chunk and the FIN tail flushes. `SO_RCVLOWAT` caps at ~rcvbuf/2,
rcvbuf caps at `net.core.rmem_max`.

## Harness

`~/work/io-uring-coro-bench/scripts/`: `setup-box.sh up|down`, `measure-fixed-ab.sh
<epoll|copy|anon|fixed>`, `measure-recvzc-ab.sh <copy|recvzc>`. Scratchpad spikes: `rcvlowat_spike.c`,
`recvzc-test.sh`. See [[ats-benchmarking-pitfalls]] before trusting any number.
