# io_uring perf results — session 2026-06-28

Consolidated A/B measurements for the io_uring net-path + registered-arena work, so the numbers are
easy to look back at (the `findings/*.txt` in the bench repo get overwritten each run).

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

## Recv zero-copy: cache-miss pass-through (T3.4)

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

CAVEATS:
- recvzc shows MORE wrk timeouts (16/42/66 vs copy 13) = coalesce LATENCY (waiting 256K) -> occasional
  tail/HoL stalls under load. Real latency-vs-throughput tradeoff.
- 256K lowat is a best-case. PROD CONSTRAINT: a high SO_RCVLOWAT is unsafe in general -- it only works
  when you KNOW >= lowat more bytes are coming (known-large plain-HTTP Content-Length). TLS (record-
  based) + H2 (multiplexed frames) make the next-step byte count unpredictable -> high lowat can stall.
  Shippable target = the MINIMAL lowat above the ZC crossover (~128K per the cold sender_zc microbench),
  not 256K. Re-measure at the minimal lowat before committing.

## `SO_RCVLOWAT` + io_uring recv spike (scratchpad/rcvlowat_spike.c)

io_uring recv honors `SO_RCVLOWAT` ONLY with `IORING_RECVSEND_POLL_FIRST` (a per-SQE flag) -- without it
the inline non-blocking recv ignores rcvlowat under load (first cqe = one 8K chunk). With it, every
completion is a coalesced >= rcvlowat chunk and the FIN tail flushes. `SO_RCVLOWAT` caps at ~rcvbuf/2,
rcvbuf caps at `net.core.rmem_max`.

## Harness

`~/work/io-uring-coro-bench/scripts/`: `setup-box.sh up|down`, `measure-fixed-ab.sh
<epoll|copy|anon|fixed>`, `measure-recvzc-ab.sh <copy|recvzc>`. Scratchpad spikes: `rcvlowat_spike.c`,
`recvzc-test.sh`. See [[ats-benchmarking-pitfalls]] before trusting any number.
