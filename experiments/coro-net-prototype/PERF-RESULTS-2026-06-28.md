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
| **master** (epoll net path)  | **0.3548** | 659K      | 0        | 0         |
| **best** (io_uring+arena+ZC) | **0.1927** | 574K      | ~1285    | **0**     |

**-46% cpu/1k (1.84x requests per CPU-second), true zero-copy on the NIC.** reps: epoll
0.3548/0.4286/0.3381, fixed 0.1927/0.1854/0.2015.

## Decomposition: copy vs anon-send_zc vs fixed-arena (disk-served 1 MiB)

`measure-fixed-ab.sh copy|anon|fixed` — all io_uring on; isolates the send mechanism.

| mode                       | cpu/1k     | vs copy  | instr/req | zc_copied |
| -------------------------- | ---------- | -------- | --------- | --------- |
| copy (io_uring, ZC off)    | 0.3147     | —        | 639K      | 0         |
| anon `send_zc`             | 0.2079     | **-34%** | 680K      | 0         |
| fixed (arena `send_zc`)    | 0.1666     | **-47%** | 525K      | **0**     |

The ladder: epoll 0.355 -> io_uring-copy 0.315 (batched submission) -> anon-ZC 0.208 -> fixed-arena-ZC
~0.17-0.19. anon spends MORE instructions (per-send page pinning) yet wins on cpu by removing the 1 MiB
memcpy's memory-bandwidth cost; fixed removes the pinning too. Confirms T3.1 (lock-free pool) + T3.3
(size classes) did not regress the arena win (fixed -47% vs the pre-refactor -42%).

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
