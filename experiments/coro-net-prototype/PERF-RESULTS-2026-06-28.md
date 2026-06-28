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

| mode                         | cpu/1k     | instr/req | zc_fixed | zc_copied |
| ---------------------------- | ---------- | --------- | -------- | --------- |
| **master** (epoll net path)  | **0.3218** | 654K      | 0        | 0         |
| **best** (io_uring+arena+ZC) | **0.1789** | 583K      | ~1300    | **0**     |

**-44% cpu/1k (1.8x requests per CPU-second), true zero-copy on the NIC.** From the single-matrix step
ladder below (epoll 0.3292/0.3218/0.3160, fixed 0.1788/0.1789/0.1777 -- very low variance). A separate
2-mode run on a hotter box read epoll 0.3548 -> fixed 0.1927 (-46%); same story, absolutes drift.

## Step ladder: epoll -> io_uring -> zero-copy -> arena (one matrix, disk-served 1 MiB)

`measure-fixed-ab.sh epoll|copy|anon|fixed` x3 interleaved -- all four steps in ONE run so the
absolutes are directly comparable. Each row adds one optimization.

| step                       | what it adds                              | cpu/1k     | step Δ   | vs master | instr/req |
| -------------------------- | ----------------------------------------- | ---------- | -------- | --------- | --------- |
| 1. epoll (master)          | stock UnixNetVConnection, copy every byte | **0.3218** | —        | —         | 654K      |
| 2. + io_uring (copy)       | batched SQE submission, still copy sends  | **0.3106** | -3.5%    | -3.5%     | 637K      |
| 3. + zero-copy (anon)      | no send memcpy (pages pinned per send)    | **0.2025** | -34.8%   | -37%      | 674K      |
| 4. + arena (send_zc_fixed) | registered buffers, no per-send pin       | **0.1789** | -11.7%   | **-44%**  | 583K      |

reps: epoll 0.3292/0.3218/0.3160, copy 0.3197/0.3106/0.3093, anon 0.2025/0.2010/0.2083, fixed
0.1788/0.1789/0.1777 (very low variance). zc_copied=0 throughout the ZC steps (true NIC zero-copy).

Shape: step 2 (batched submission) is modest on LARGE objects (-3.5%; its big win is small-object /
moderate concurrency). Step 3 (zero-copy send) is the giant leap -- removing the 1 MiB memcpy's
memory-bandwidth cost is -35% EVEN THOUGH it spends more instructions (per-send page pinning, instr/req
637K->674K). Step 4 (arena) pays off that pinning debt: send_zc_fixed drops instr/req to 583K (below
epoll) and shaves another -12%. Confirms T3.1 (lock-free pool) + T3.3 (size classes) did not regress the
arena win.

(An earlier separate copy/anon/fixed-only matrix, different box thermal state, read copy 0.3147 / anon
0.2079 / fixed 0.1666 -- same shape; trust the single-matrix ladder above for the step deltas.)

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
