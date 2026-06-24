# io_uring + coroutine net path — performance study

A hypothesis → experiment → result → conclusion log for the io_uring/coroutine
network path (branch `io-uring-coroutine-wip`) versus the epoll baseline (master).
Companion to `DECISIONS.md` (which records *what was decided*); this file records
*what was measured and why*.

## Rig and method (read first)

- **Box:** i9-12900K (hybrid: 8 P-cores + 8 E-cores), Ubuntu 24.04 HWE, kernel
  6.17, liburing 2.4. During runs: `performance` governor, turbo **off**
  (`no_turbo=1`), `perf_event_paranoid=-1`.
- **Pinning:** ATS confined to a cgroup-v2 cpuset `atsbench` = P-cores `0,2,4,6`
  (taskset is insufficient — hwloc rebinds ET_NET threads); the `wrk2` client to
  `clibench` = `8-23`. 4 ET_NET threads, 1 accept thread.
- **Gold metric:** `cpu/1k-req` = cgroup `cpu.stat` `usage_usec` delta ÷ requests.
  This counts only ATS user+sys CPU (softirq and the client are excluded), so it is
  a clean per-request efficiency signal independent of who the bottleneck is.
- **Workload:** `wrk2` open-loop constant rate, HTTP/1.1 keep-alive, reverse-proxy
  + remap, served from a 100% RAM-cache HIT (origin nginx out of path). Validated
  every run by `RAM% = 100·cache_hit_mem_fresh/cache_hit_fresh == 100`.
- **A/B isolation:** unless noted, master vs io_uring is the **same Release+fp
  binary** with `proxy.config.net.io_uring.enabled` toggled 0/1 — so the only
  variable is the net path (+ the accept-thread topology the flag selects). This
  removes the cross-campaign drift that weakened the earlier frame-pool numbers.
- Binaries are Release `-O3 -fno-omit-frame-pointer` from the current tree
  (`IOU_FRAME_IOV=16`, all five fixes), installed at `/tmp/ts-iou-fp`.

## Background: the established result this study builds on

The io_uring net path was once **+20.9% cpu/req** vs epoll with a collapsing p99
tail. Five fixes (documented in `DECISIONS.md` D29 and `io-uring-perf-baseline`)
brought it to parity. Ranked by impact: (1) shrink the inline `iovec` from
`NET_MAX_IOV`(1024 ⇒ 16 KB) to 16 — the 16 KB array lived in the *heap coroutine
frame* pinned across the await, where master keeps it as a cache-warm *stack* local;
(2) block directly in `io_uring_submit_and_wait` instead of bridging completions
through an eventfd into `epoll_wait`; (3) opportunistic synchronous write; (4)
single-buffer `recv`/`send` for the 1-block case; (5) unregister the now-dead
completion eventfd.

**Anchor (this session, n=5, 4 KB objects, 120k req/s):** master 0.0139 vs io_uring
0.0140 cpu/1k = **+0.7%**, p99 ~2.1 ms both. The harness/box reproduce the recorded
parity, so the experiments below stand on a validated baseline.

## Summary of findings

| # | Question | Answer |
|---|---|---|
| H1 | iovec size vs transfer size | Sensitivity peaks at *medium* sizes (64 KB: ±10%, U-curve), **vanishes** for large (copy-bound). `IOU_FRAME_IOV=16` is in the flat optimum; the real risk is the *large* frame, not the small one. The "larger reads need larger iovec" intuition is wrong. |
| H2 | Run without the eventfd? | **Yes for plain HTTP** (and default on-thread io_uring AIO). But the branch silently dropped the **cross-thread wakeup doorbell**, stalling cross-thread work up to the 60 ms heartbeat. A multishot poll on `thread->evfd` restores it: **p99 62 ms → 2.2 ms, perf-neutral.** *(actionable fix)* |
| H3 | Real TCP, not loopback | **Parity holds** (+1.9% at 4 KB, +0.0% at 64 KB on veth MTU 1500). The loopback result was not an artifact. |
| H4 | Frame contiguity | Contiguous-slab arena ≈ scattered freelist (±1%, noise). Not a meaningful lever at this scale — the frame is already small. Hypothesis not supported. |
| H5 | Where the residual lives | Clean n=3: io_uring **+1% instructions / +2% cycles** vs master (corrects the earlier "fewer instructions" claim). Residual = locality (cache +27%, dTLB +28%, branch-miss +17%) in the two `.actor` coroutine bodies + `submit_and_wait`. No single hot spot. |
| H6 | Cheaper / syscall-free write | **Pure async batched write** removes the per-request `sendmsg` (0.98→0/req), halves net syscalls, and is **−1.8% cycles/req** (IPC 1.368→1.400) — reversing the earlier EXP-1b. Moves io_uring from +2.7% to **+0.8% cycles** vs master. *(actionable optimization)* |
| H7 | Where the misses land (precise/leaf) | Residual is **memory-footprint, not control-flow**: LLC +79% & dTLB-walks +59% but **L1 ≈0** — cold-line/capacity at `_read.actor` (frame) + `submit_and_wait` (rings). Branch +13% is kernel SQE-issue; the **coroutine resume jump is BTB-predicted, not a miss source** (theory refuted). |
| H8 | Huge pages | **Not a lever.** THP/glibc-tunable can't reach ATS memory (`AnonHugePages=0`, 6 cells). The working ATS hugetlb knob backs only the shared iobuffer arena (lowers both arms, no cpu/1k benefit), never the frames/rings. dTLB residual is <1% cpu anyway. |
| H9 | Bigger block / large-object gap | Block size is **not** the lever: CQE/req immovable (67.6→67.0) across 8 KB→256 KB→+2 MB SO_RCVBUF (refutes `ceil(size/block)`; backpressure sets it). io_uring is **+17% on 1 MB passthrough**, and it's **ops-structural** (67 one-op-per-resume CQEs vs epoll's drain loop), not locality — so co-location won't fix it; fewer ops/req (multishot) will. |
| H10 | Mitigate the frame cost | **No lever found.** Shrinking the frame (iov 16→8) is a dead end (cost is the *allocation*, not the size). Frame-in-VC (embed the frame in the VC, drop the pool) is correct + clean but **perf-neutral** (interleaved A/B: −0.5%, within noise) — the FramePool already keeps the frame hot — and costs 1.28 KB/VC. **Keep the pool.** The frame is not what holds io_uring back. |
| H11 | Op-count audit (SQE vs syscall) | io_uring **wins on syscalls** (1 MB pass: 18.2 `io_uring_enter` vs 52.6; hot path 1.71 ops vs 2.93 — epoll wastes an EAGAIN-probe recvmsg). But at the **op** level it does ~10% more, all **sends** (28.8 vs 17.5): it emits **one send per recv completion** (`READ_READY` signalled after every recv) where epoll coalesces ~2 reads/send. Each extra send = one extra coroutine resume. |
| H12 | Write-coalescing | **Tried, rejected — a pessimization.** Accumulating reads before signalling cuts sends 28.8→16.1 (below epoll) and total ops below epoll, **but raises cpu/1k ~2% and instr/req +6%** (clean). H6's async write already amortized the send syscalls, so coalescing removes near-free syscalls while adding multi-block `sendmsg` build + accumulation cost. **Keep per-block sends.** |

**Two actionable code changes came out of this:** (1) the cross-thread doorbell
(correctness, free) and (2) the async batched write (perf). Both are validated below.
The arena (H4) is not worth keeping. `IOU_FRAME_IOV=16` (H1) is confirmed optimal.

---

## H1 — IOVEC size vs transfer size (Q2)

**Hypothesis.** `IOU_FRAME_IOV` trades two costs: a *small* value shrinks the
coroutine frame (cache/dTLB friendly) but caps how many buffer blocks one recv/send
op can carry, forcing more ops + loop iterations on large transfers; a *large* value
cuts ops but re-bloats the frame. There should be a knee, and it may move with the
object size — larger objects should favor a larger iovec.

**Experiment.** Build one binary per `IOU_FRAME_IOV ∈ {1,4,16,64,256,1024}`
(only `IOUringNetVConnection.cc.o` differs). For object sizes 64 KB / 1 MB / 8 MB
(multi-block regime), measure cpu/1k at a saturating rate, with an epoll reference
(iovec-independent) per size. 3 rounds each.

**Result.**

cpu/1k (median of 3 rounds), Δ vs the epoll reference at each size:

| IOU_FRAME_IOV | 64 KB (CPU-bound, ~190k rps) | 1 MB (bw-bound, ~20 GB/s) | 8 MB (client-bound, ~52 rps) |
|---|---|---|---|
| epoll (1024 stack) | 0.0209 | 0.1992 | 3.034 |
| 1 | 0.0231 (**+10.5%**) | 0.2014 (+1.1%) | 2.990 (−1.5%) |
| 4 | 0.0203 (−2.9%) | 0.2004 (+0.6%) | 2.962 (−2.4%) |
| 16 | 0.0203 (−2.9%) | 0.2022 (+1.5%) | 3.019 (−0.5%) |
| 64 | 0.0203 (−2.9%) | 0.2002 (+0.5%) | 2.991 (−1.4%) |
| 256 | 0.0205 (−1.9%) | 0.2026 (+1.7%) | 2.948 (−2.9%) |
| 1024 | 0.0217 (**+3.8%**) | 0.2032 (**+2.0%**) | 3.003 (−1.0%) |
| spread (min→max) | **±10%** | ±1% | ±2% (noise) |

**Conclusion.** The intuition that *larger* transfers favor a *larger* iovec is **not
supported** — it is the opposite. Sensitivity to `IOU_FRAME_IOV` peaks at *medium*
object sizes and vanishes for large ones:

- **64 KB (CPU-bound):** a clean U-curve. iov=1 costs **+10.5%** (a 64 KB object is
  ~2 blocks, so a 1-iovec op needs 2 recv/send ops + 2 loop iterations); the 16 KB
  frame at iov=1024 costs **+3.8%** (cache/dTLB). The flat optimum is iov 4–64, where
  io_uring *beats* epoll by ~3%. This is the regime where per-op overhead is a
  meaningful fraction of the per-request cost.
- **1 MB / 8 MB:** all values collapse to within ±1–2% (noise). Once the per-request
  data **copy** dominates (20 GB/s loopback at 1 MB; client-bound at 8 MB), the
  op-count cost is negligible — even iov=1 (forcing the most ops) is within noise.
  The only signal that survives is the *negative* one: iov=1024 is the worst at every
  size (+2.0% even at 1 MB), i.e. the large frame's cache cost persists while its
  op-count benefit does not.

So `IOU_FRAME_IOV=16` is well-chosen and robust: optimal in the medium regime,
indistinguishable from optimal at large sizes, and far from the costly extremes. The
real risk a designer should avoid is the *large* inline iovec (frame bloat), not the
small one — the small inline iovec does not hurt large transfers on this path. (The
read path is structurally identical, same constant; H6 and the cache-miss large-read
run below confirm the read side behaves the same.)

---

## H2 — Cross-thread wakeup correctness without the eventfd (Q1)

**Hypothesis.** Two eventfds exist: (A) the io_uring *completion* eventfd that
bridges CQEs into `epoll_wait`, and (B) the per-EThread *wakeup* eventfd that
`NetHandler::signalActivity()` writes for cross-thread wakeups. The direct-blocking
io_uring path unregisters (A) — correct, it is pure epoll-bridge overhead. But once
a net thread blocks in `io_uring_submit_and_wait`, a cross-thread `write(thread->evfd)`
(B) wakes nothing (B is in neither epoll nor the ring), so cross-thread reenables and
timers injected after the thread blocked are only serviced on the next CQE or the
≤60 ms heartbeat. This is invisible on a single-thread RAM-hit benchmark but is a
real latency regression for disk-cache / multi-thread / plugin work. The fix: arm a
**multishot poll on `thread->evfd` inside the ring** (the io_uring-native equivalent
of `AsyncSignalEventIO`), so the cross-thread write produces a CQE that breaks
`submit_and_wait`.

**Experiment.** (a) Confirm plain HTTP runs correctly with the completion eventfd
gone (it already does — `disable_eventfd` at runtime). (b) Add the multishot-poll
doorbell and confirm it is perf-neutral on the RAM-hit path. (c) Try to reproduce
the cross-thread stall by forcing `proxy.config.aio.mode=thread` (so disk-cache reads
complete on an ET_AIO thread and reenable the net VC cross-thread), low concurrency,
and compare latency: epoll vs io_uring-no-doorbell vs io_uring-doorbell.

**Result.**

- **Perf-neutral (variants A/B):** doorbell vs baseline io_uring = 0.0138 vs 0.0139
  cpu/1k at 4 KB, 0.0201 vs 0.0204 at 64 KB — within noise. The multishot poll arms
  one SQE per net thread and only completes when another thread rings the doorbell,
  which plain HTTP never does, so steady-state cost is zero.
- **Why plain HTTP is already safe without the eventfd:** with the default
  `aio.mode=auto`, disk-cache reads use **io_uring on the net thread's own ring**, so
  their completions are CQEs on that same ring — they wake `submit_and_wait` directly,
  no cross-thread doorbell needed. A plain-HTTP connection's work (accept, read,
  cache, write) all stays on its own ET_NET thread. So the cross-thread doorbell gap
  does **not** bite the target workload.
- **Cross-thread stall reproduction (forced `aio.mode=thread`, conns=4, disk-cache):**

  | net path | p50 | p99 | p99.9 |
  |---|---|---|---|
  | epoll (io_uring build, enabled=0) | 1.13 ms | **62.1 ms** | 62.3 ms |
  | io_uring, no doorbell | 1.11 ms | **61.6 ms** | 61.7 ms |
  | io_uring, **doorbell** | 1.07 ms | **2.21 ms** | 11.7 ms |

  The doorbell cuts p99 from ~62 ms (≈ the 60 ms heartbeat cap) to 2.2 ms — a **28×**
  tail improvement when work arrives cross-thread. Same at conns=32 (p99 61.3/61.6 ms
  without → 2.08 ms with), so it is not a low-concurrency artifact.

- **Scope of the underlying bug (verified in code, `UnixNet.cc:189-201`):** the choice
  between `IOUringEventIO` (registers the io_uring completion fd) and
  `AsyncSignalEventIO` (registers `thread->evfd`, the cross-thread doorbell) is made at
  **compile time** (`#if TS_USE_LINUX_IO_URING`), not by the runtime flag. So *any*
  io_uring-enabled build never registers `thread->evfd` — the cross-thread doorbell is
  missing on **both** the io_uring net path and its epoll fallback (that is why the
  "epoll" arm above also stalls at 62 ms). True master (USE_IOURING=0) installs
  `AsyncSignalEventIO` and does not have this gap. So this is a **latent regression
  introduced by the io_uring branch**, not a property of io_uring itself.

**Conclusion.** Three things. (1) **Yes — plain HTTP runs correctly without the
completion eventfd**, and the default `aio.mode=auto` keeps even disk-cache work on
the connection's own ET_NET ring, so the cross-thread gap does not bite the target
workload. (2) The completion eventfd (A) is correctly gone; it was pure
epoll-bridge overhead. (3) But the branch *did* silently drop the cross-thread
doorbell (`thread->evfd`) for the whole io_uring build, which stalls genuinely
cross-thread work (thread-mode AIO, cross-thread continuations, future H2) up to the
heartbeat. The **multishot poll on `thread->evfd`** restores it — a one-SQE-per-thread
doorbell that is provably perf-neutral on the hot path (it only completes when rung)
and fixes the 62 ms tail. This is the correct way to be "fully io_uring without the
eventfd": drop the *completion* eventfd, but keep a doorbell on the *wakeup* eventfd —
in the ring, not in epoll. (Caveat: the doorbell is armed only on the io_uring-enabled
path; the io_uring build's epoll *fallback* still lacks it and should restore
`AsyncSignalEventIO` when `enabled=0`.)

---

## H3 — Real TCP vs loopback (Q3)

**Hypothesis.** The parity result was measured on loopback (MTU 65536, no real
segmentation/softirq). On a real TCP path (MTU 1500, real segmentation) the net-path
CPU difference is the coroutine state machine, which is independent of segmentation,
so parity should hold; absolute cpu/req rises for both.

**Experiment.** veth pair to a client netns, MTU 1500, GRO/GSO/TSO off (real
segmentation, like a NIC without offload). Re-run the master-vs-io_uring A/B at
4 KB and 64 KB. ATS cgroup-pinned (host); wrk in the netns.

**Result.**

| object | epoll cpu/1k | io_uring cpu/1k | Δ | vs loopback |
|---|---|---|---|---|
| 4 KB | 0.0156 | 0.0159 | +1.9% | (loopback +0.7–1.5%) |
| 64 KB | 0.0493 | 0.0493 | +0.0% | (loopback −2.4%) |

**Conclusion.** **Parity holds on a real-TCP path.** Absolute cpu/req rises (4 KB
0.0156 vs loopback 0.0137; 64 KB 0.0493 vs 0.0209 — real 1500-byte segmentation costs
more socket-layer work per request, counted in ATS's sys time), but the
io_uring-vs-epoll *relationship* is unchanged: +1.9% at 4 KB, exact parity at 64 KB,
both within the loopback band. The earlier loopback-only result was not a loopback
artifact — the coroutine/ring cost is independent of segmentation, as hypothesized.
This closes the prior "proven only on loopback" scope caveat for the
client-facing cache-hit path.

_Origin-facing cache-MISS large read (passthrough, no cache, 1 MB from origin →
client; the origin-facing `_read` over io_uring recv):_ at a clean sub-saturation
rate (4000 req/s), cpu/1k = epoll 0.4399 vs io_uring 0.4403 = **+0.1%, parity.** (A
naive saturating run earlier showed a ~16% throughput gap, but that was a closed-loop
ceiling artifact, not a CPU-efficiency difference — at a controlled rate the per-
request CPU is equal.) This extends parity to the origin-facing read path and the
cache-MISS scenario, two more of the previously-unmeasured scopes.

---

## H4 — Coroutine frame contiguity (Q4)

**Hypothesis.** Frames are individual `::operator new` blocks recycled by an
intrusive LIFO freelist — scattered across the heap. A contiguous-slab arena (CAP
frames of one size packed into one region) should cut dTLB/cache misses. BUT the
prior adversarial review found the pool win was primarily an *instruction-count*
(malloc-removal) effect, dTLB only ~26–42% of saved cycles; and at conns≤200 the
LIFO working set is tiny and likely already resident. So the expected effect is
small at this scale, larger only at high connection counts.

**Experiment.** Drop-in arena allocator (`FramePool` internals replaced: CAP frames
of one size class packed into one contiguous slab, bump-allocated, intrusive LIFO
freelist within the slab; same public API, same `-f`/`-F` bypass). A/B vs the
scattered freelist at 4 KB and 64 KB.

**Result.**

| | 4 KB cpu/1k | 64 KB cpu/1k |
|---|---|---|
| scattered freelist (baseline) | 0.0139 | 0.0204 |
| contiguous slab (arena) | 0.0137 | 0.0201 |
| Δ | −1.4% | −1.5% |

**Conclusion.** The arena is **at most a ~1% improvement, inside run-to-run noise** —
not a clear win. This matches the prediction and the prior adversarial review: the
frame pool's real win was eliminating the per-op malloc/free *instruction* stream,
which *both* allocators already do; contiguity only addresses locality, and the
locality headroom is tiny here. Two reasons it can't be large: (1) the frame is
already small (16 inline iovec ⇒ ~300 B), so even scattered frames touch few pages;
(2) LIFO reuse at conns ≤ 600 keeps the hot working set to a handful of frames that
stay cache/TLB-resident regardless of where `malloc` placed them. The whole io_uring
dTLB *excess* over epoll is ~2 misses/req (H5: 9.5 vs 7.4); at ~20–40 cycles/walk
that caps any contiguity win at ≈0.1% of the 42k cycles/req — so a high-connection
campaign was not worth running. **The user's hypothesis (non-contiguity hurts) is not
supported at this scale.** It is directionally real but immaterial; the lever that
*would* matter (frame size) was already pulled by `IOU_FRAME_IOV=16`.

---

## H5 — Where the residual lives: cache + branch profile

**Hypothesis.** Post-fix, io_uring does fewer instructions/req than master but
~equal cycles; the residual is the SQ/CQ ring's cache cost. A branch-miss profile
should show the coroutine state machine's branches; a cache profile should localize
the misses to the ring/CQE handling.

**Experiment.** `evidence2.sh` — 3 windows, request-normalized, instructions /
cycles / branches / branch-misses / cache-misses / dTLB; plus `perf record` symbol
diff io_uring vs master.

**Result.** Per request, median of 3 windows (~1.8M reqs each, RAM%=100, same binary
toggled):

| metric / req | master (epoll) | io_uring (opt) | Δ |
|---|---|---|---|
| instructions | 58,055 | 58,637 | **+1.0%** |
| cycles | 41,551 | 42,386 | **+2.0%** |
| branches | 10,568 | 10,709 | +1.3% |
| branch-misses | 76.4 | 89.1 | **+16.6%** |
| cache-misses | 76.1 | 96.7 | **+27%** |
| dTLB-load-misses | 7.42 | 9.48 | **+28%** |
| IPC | 1.396 | 1.381 | −1.1% |
| CQE/req | 0 | 1.01 | the recv completion |

**Conclusion.** This **corrects** an earlier claim (recorded as "io_uring now does
*fewer* instructions/req than master"). That comparison was across *separate*
measurement sessions; the clean within-session n=3 A/B shows io_uring at **+1.0%
instructions / +2.0% cycles** — still parity-class, but it does *not* do less work.
The residual ~+2% cycles is roughly half a small instruction overhead and half a
~1% IPC penalty, and the IPC penalty is explained by markedly worse locality:
**+27% cache-misses, +28% dTLB, +17% branch-misses per request.** The extra cache/TLB
footprint is the SQ/CQ rings + the CQE completion records + the heap coroutine frame
(even at 16 entries it is touched memory master keeps on the warm stack); the extra
branch-misses are the coroutine state machine's resume/suspend dispatch that master's
straight-line `net_read_io`/`load_buffer_and_write` does not have. Exactly one CQE
per request (the read recv) — the write is the sync `sendmsg`, so it generates none.
This is the honest floor of the current design: ~2% cycles, locality-bound, not
instruction-bound. <!-- perf record symbol diff appended below -->

_Symbol-level perf diff (io_uring − master), post-fix:_

```
io_uring ADDS (user, coroutine machinery):
  +1.55%  IOUringNetVConnection::_read [clone .actor]
  +1.07%  IOUringNetVConnection::_write [clone .actor]
  +0.77%  IOUringContext::submit_and_wait
  +0.47%  IOUringNetVConnection::_read_signal_and_update
io_uring ADDS (kernel, ring dispatch):
  +0.42 llist_reverse_order  +0.37 task_work_run  +0.26 fget  +0.22 io_free_batch_list
  +0.59 asm_sysvec_reschedule_ipi  (io_uring task_work reschedule IPIs)
io_uring REMOVES (kernel, epoll + syscall entry):
  -0.70 entry_SYSCALL_64  -0.57 sock_poll  -0.40 fdget  -0.34 NetHandler::waitForActivity
  -0.56 pthread_{en,dis}able_asynccancel  -0.24 copy_iovec_from_user  -0.24 _copy_from_user
```

This is the *small* post-fix version of the pre-fix diff (which had `_read.actor`
+7.0% and `_write.actor` +4.1% — the 16 KB frame). With the frame shrunk, the residual
is just the coroutine state machines' dispatch (resume/suspend + frame touch) and
`submit_and_wait`, partly offset by the epoll poll-callback + syscall-entry machinery
io_uring removes. The +0.77% in `submit_and_wait` and the reschedule-IPI lines are the
ring's own cost. Net: the residual is genuinely the coroutine + ring machinery, ~2%,
and there is no single hot spot left to cut — it is spread across the two `.actor`
bodies. (The `_write.actor` line is the sync-write baseline; H6's async write trims
its syscall-entry component.)

---

## H6 — Read primitives & cheaper writes

**Hypothesis.** Without a provided-buffer ring (deferred), the only realistic read
primitives are `recv` (1 block) and `recvmsg` (multi) — already chosen. For writes,
the steady-state path is a sync `sendmsg` (1 syscall, no `io_uring_enter`); a pure
async io_uring send riding the batched `submit_and_wait` would cost ~0 extra syscalls
(amortized) but add a CQE + coroutine resume per write. Whether sync or batched-async
wins is the question.

**Experiment.** A/B the current opportunistic sync `sendmsg` vs a pure async io_uring
send that rides the batched `submit_and_wait` (`ts-wasync`); cpu/1k at 4 KB / 64 KB
and a syscall-level profile.

**Result.**

| write strategy | 4 KB cpu/1k | 64 KB cpu/1k | 64 KB p99 |
|---|---|---|---|
| sync sendmsg (baseline) | 0.0139 | 0.0204 | 240–600 ms |
| pure async, batched (wasync) | **0.0136** | **0.0198** | **3–32 ms** |
| Δ | −2.2% | −2.9% | tail collapses |

_Syscall-level confirmation (per request):_

| per req | sync `sendmsg` (baseline) | pure async, batched |
|---|---|---|
| `sendmsg` | 0.98 | **0** |
| `io_uring_enter` | 0.345 | 0.519 |
| total net syscalls | ~1.33 | **~0.52** |
| CQEs | 1.01 (recv only) | 2.01 (recv + send) |
| cycles/req | 42,671 | **41,897 (−1.8%)** |
| IPC | 1.368 | **1.400** |

The mechanism is exactly as hypothesized: the send SQE rides the one
`submit_and_wait` per loop iteration, so at 120k req/s many sends batch into a single
`io_uring_enter`; the per-request `sendmsg` syscall (0.98/req) disappears and total
net syscalls roughly halve. Instructions tick up +0.5% (the suspend/resume) but cycles
drop −1.8% because IPC improves (fewer syscall-entry stalls). Relative to the H5
master baseline (41,551 cyc/req), this moves io_uring from +2.7% (sync) to **+0.8%
(async) cycles/req**.

**Honesty note on the metrics.** The 4 KB *cpu/1k* numbers (0.0136 wasync vs 0.0139
baseline vs 0.0137 epoll vs 0.0138 combined) sit inside the harness's ~±1.5% cpu/1k
noise floor and cannot, on their own, resolve a 1–2% effect — the wasync win rests on
the *cleaner* signals: cycles/req (−1.8%, n≈1.8M-req windows, tight), syscalls/req
(`sendmsg` 0.98→0), the 64 KB cpu/1k (−2.9%, clearer because the per-request cost is
larger), and the 64 KB tail collapse. Treat the cycles/syscall evidence as
load-bearing, not the 4 KB cpu/1k.

**Conclusion.** This **reverses the earlier EXP-1b finding** that sync write was ~1.2%
cheaper. EXP-1b was measured *before* the frame
shrink + direct-blocking fixes; on the current path the async write's CQE/resume is
cheap (small pooled frame) and, crucially, the send SQE rides the one
`submit_and_wait` per loop iteration — so at 120k req/s many sends batch into a single
`io_uring_enter`, costing ~0 marginal syscalls, versus one `sendmsg` syscall per
request on the sync path. The result is a small but consistent CPU win *and* a large
64 KB tail-latency improvement. This is the answer to "avoid the write syscall with
better performance": on the optimized path, batched async send is both
syscall-light and faster. (SQPOLL — no `io_uring_enter` at all — was characterized but
not adopted: it dedicates a kernel poller core, the wrong trade for CPU/req.)

_Combined with the doorbell (the ship candidate), vs epoll:_ 4 KB +0.7% (noise),
**64 KB −4.3%** (io_uring wins; baseline was −2.4%, so the async write adds ~2 more
points at medium size and collapses the 64 KB write tail: p99 16–154 ms vs epoll
516–571 ms), cache-MISS 1 MB +0.1% (parity). So the net effect of the two changes is
parity-or-better everywhere measured, with the medium-object regime now a clear win.

---

## H7 — Where the misses physically land (Q4, precise/leaf attribution)

**Hypothesis.** H5 showed the residual is "locality" but attributed it only to whole
functions via cycle sampling. *Which* misses (L1 / LLC / dTLB / branch) and *which
leaf instructions*? And is the coroutine resume indirect-jump the branch-miss source,
as theory predicts?

**Experiment.** Same FP binary toggled `enabled=1`/`=0` under steady 4 KB RAM-hit load
(4 KB maximises coroutine-ops/sec, so the machinery's misses dominate over body-copy
misses). `perf record` with **precise (PEBS)** events + fp call graph:
`br_misp_retired.all_branches`, `dtlb_load_misses.walk_completed`,
`mem_load_retired.l1_miss`, `mem_load_retired.l3_miss`. Leaf attribution via
`--no-children`.

**Result.** Window totals (≈ per-req at equal load):

| event | io_uring | epoll | Δ |
|---|---|---|---|
| LLC (L3) load-misses | 14.2 M | 7.95 M | **+79%** |
| dTLB page-walks completed | 28.3 M | 17.8 M | **+59%** |
| branch mispredicts | 228.8 M | 202.0 M | +13% |
| L1 load-misses | 1840 M | 2050 M | **≈0 (−10%)** |

Leaf (self%) sites:
- **L3 + dTLB** concentrate in **`_read.actor`** (the 528 B heap coroutine frame) and
  **`submit_and_wait`** (the SQ/CQ rings) — io_uring-specific; epoll's counterparts are
  `net_read_io` + `ReadWriteEventIO::process_event`.
- **Branch** misses are dominated in *both* arms by `nf_hook_slow` (conntrack — a
  loopback/veth rig artifact). The io_uring-specific branch leaves are kernel-side
  `__io_issue_sqe` / `io_sendmsg` (the send now runs inside `io_uring_enter`), replacing
  epoll's `__x64_sys_sendmsg`. The coroutine **resume indirect-jump does not appear** as
  a leaf.

**Conclusion.** The residual is a **memory-footprint** cost, not a control-flow cost:
- **L1 is unchanged** while LLC + page-walks jump — so it is a *cold-line / capacity*
  effect (the 528 B frame and the ring pages are touched cold, once per op, on pages
  distinct from the data buffer and the VC), **not** L1 thrash.
- The **branch-miss theory is refuted**: the resume jump is BTB-predicted (each
  connection resumes to the same point repeatedly); the small branch excess is kernel
  SQE-issue, roughly a wash with epoll's syscall entry. This is a *good* surprise — the
  coroutine dispatch is cheap; the cost is the frame+ring footprint. Refines H5.

## H8 — Huge pages do not reach the io_uring path (Q3)

**Hypothesis.** The dTLB-walk excess (H7) is a page-table cost; 2 MB pages should cut it.

**Experiment.** Three escalating levers, measuring cpu/1k + `dtlb_load_misses/req`, and
— critically — **verifying the ATS process actually got huge pages** (`AnonHugePages`
in `smaps_rollup`, `HugePages_Free` drop) before trusting any delta:
(1) THP `never`/`always`; (2) `GLIBC_TUNABLES=glibc.malloc.hugetlb=1` + aggressive
khugepaged; (3) ATS's own explicit-hugetlb knob `proxy.config.allocator.hugepages=1`
with reserved `nr_hugepages`.

**Result.**
- THP (6 cells) — ATS `AnonHugePages` stayed **0** in every cell. ATS allocates through
  its own `ink_freelist` (mmap chunks) + small brk allocations; **neither is reachable**
  by khugepaged, THP, or the glibc malloc-hugetlb tunable. The dTLB numbers just bounce
  in noise (even rising for epoll-always).
- ATS hugetlb knob — *did* back **28 MB** of arena (proven: `HugePages_Free` −14 pages),
  but produced **no cpu/1k benefit** (all cells 0.0139–0.0141). It backs the **shared
  iobuffer arena**, so it lowers io_uring and epoll equally (not a parity lever), and
  never touches the FramePool frames or SQ/CQ rings — the actual io_uring dTLB excess.
- At parity the dTLB residual is **< 1% of cycles** (io_uring/epoll cpu/1k identical).

**Conclusion.** Huge pages are **not a lever** for the io_uring path: the memory that
would benefit (frames/rings) is unreachable by every stock mechanism, the working knob
helps only shared infrastructure equally, and the ceiling is sub-1% against THP's
compaction-jitter risk. Reaching the frames would require a code change to
hugepage-back the FramePool — for < 1%.

## H9 — Bigger MIOBuffer block does not cut the large-object op count (Q2); the large-object gap is ops-structural (Q1)

**Hypothesis (from the design review).** A 1 MB cache-miss passthrough recvs in 8 KB
blocks (`HttpSM.cc:1805`, `HTTP_SERVER_RESP_HDR_BUFFER_INDEX`), so a bigger block should
cut recv ops as `ceil(objsize/blocksize)` — 8 KB→256 KB = ~32× fewer CQEs/coroutine
resumes.

**Experiment.** 1 MB passthrough, io_uring vs epoll, counting CQEs/req
(`io_uring:io_uring_complete` tracepoint) and rw-syscalls/req. Then bump the origin read
buffer 8 KB→256 KB (one line, rebuild), and pair it with a 2 MB `SO_RCVBUF`. Plus a
FramePool on/off (`-f`) cell to separate locality from op-structure.

**Result.**

| arm | cpu/1k | CQE or syscalls /req |
|---|---|---|
| io_uring, 8 KB block | 0.6787 | 67.6 cqe |
| epoll, 8 KB block | 0.5810 | 53.4 syscalls |
| io_uring, 256 KB block | 0.6747 | **67.2 cqe** |
| io_uring, 256 KB + 2 MB SO_RCVBUF | 0.6752 | **67.0 cqe** |
| io_uring, 8 KB, FramePool **off** (`-f`) | 0.7381 | 67.7 cqe |

**Conclusion.**
- The CQE count is **immovable** by block or socket-buffer sizing (67.6→67.2→67.0).
  This **refutes the `ceil(objsize/blocksize)` prediction** — the per-recv size is set
  by **tunnel backpressure/flow dynamics** (the consumer drains incrementally, so each
  recv returns ~16 KB regardless of offered space), not the block index. Bigger blocks
  are not a lever.
- io_uring is **+17% cpu/1k on 1 MB passthrough** — a real gap (unlike the small-object
  parity), and it persists with the FramePool **on**. Pool-off adds +8.8%
  (frames+iobuffers) but leaves CQE/req unchanged, so the gap is **ops-structural**: io_uring
  does 67 single CQEs, one per coroutine resume; epoll drains the socket in a userspace
  loop (`UnixNetVConnection.cc:542 do…while(r==rattempted)`), 53 syscalls, fewer
  event-loop re-entries. **Frame–VC co-location targets only the locality slice the pool
  already captures — not this gap.** The lever for the large-object case is fewer ops/req
  (multishot recv — deferred), or a coroutine inner drain-loop.

## H10 — Mitigating the coroutine frame cost (can we make io_uring's efficiency show?)

**Hypothesis.** H7 named the 528/536 B heap coroutine frame the top LLC/dTLB leaf.
If that footprint is the thing keeping io_uring at parity rather than ahead, then
either (a) shrinking the frame or (b) co-locating it with the VC should recover cycles
and turn the small-object parity into a win. Two mitigations, while the code is still
~1:1 with master (before multishot / provided buffers):
- **Shrink:** drop `IOU_FRAME_IOV` 16→8 (the `iovec[16]` is 256 B of the 528 B frame).
- **Frame-in-VC:** make each coroutine's frame a fixed member of the VC
  (`_read_frame` / `_write_frame`), with a custom `operator new` that returns the
  embedded buffer and a no-op `operator delete`. There is at most one `_read` and one
  `_write` live per VC, and the VC already may not be freed with an op in flight, so a
  per-VC buffer is exactly as long-lived as needed — and it removes the per-op pool
  allocation *and* puts the frame on the VC's own cache lines. (Patch:
  `io-uring-coro-bench/prototypes/frame-in-vc-colocation.patch`.)

**Experiment.** 4 KB RAM-hit (1 frame/req) and 1 MB passthrough (frame touched ~67×/req,
where a per-frame effect is amplified). For frame-in-VC, a **true interleaved A/B** —
both binaries built, alternated at a fixed sub-saturation rate (4000 rps) to cancel
drift, n=4 each — because the saturated large-object cpu/1k has a ±5–6% noise floor that
single samples cannot see through.

**Result.**

| mitigation | workload | cpu/1k | vs baseline |
|---|---|---|---|
| `IOU_FRAME_IOV` 16→8 (frame 528→400 B) | 4 KB hot | 0.0144 | +1% (noise / slightly worse) |
| frame-in-VC | 4 KB hot | 0.0142–0.0146 | flat |
| frame-in-VC (interleaved, fixed rate) | 1 MB passthrough | 0.4695 med | base 0.4719 med — **−0.5%, within noise** |

The first 1 MB frame-in-VC sample read −4.7%; reps 2–4 read +5–7%. The interleaved A/B
(base {0.457, 0.464, 0.480, 0.480} vs coloc {0.456, 0.459, 0.480, 0.527}) settles it:
the distributions overlap; the median gap is 0.5%, inside the noise floor.

**Conclusion.** **Neither mitigation moves cpu/1k** — the frame cost is already paid down:
- **Shrinking is a dead end.** The cost was never the frame's *size* — H7's top dTLB
  leaves were `freelist_new`/`thread_alloc` (the *allocation*) and the cold frame line,
  not the byte count. Below iov=16 you lose op-coverage (H1) for no locality gain.
- **Frame-in-VC is correct and clean but perf-neutral.** The FramePool (LIFO, thread-local)
  already keeps the frame hot: the alloc is a cheap inline pop and the reused frame is
  cache-resident at steady state, so removing the pool and co-locating saves nothing
  measurable — even at 67 frames/req. And it would **cost 1.28 KB on every VC**
  (`_read_frame` + `_write_frame`), borne by all connections including idle keep-alives,
  whereas the pool holds frames only for *active* ops. Worse memory scaling for no perf.

So the frame is **not** what holds io_uring back. The only remaining lever is the one H9
points to — fewer ops/req (multishot recv / provided buffers, deferred) — which attacks
the per-op CQE/resume *structure*, not the frame. **Recommendation: keep the FramePool;
do not adopt either mitigation.** The experiment is the value: it proves the frame cost is
already neutralized.

## H11 — Op-count audit: io_uring trades syscalls for ops, and its writes are un-coalesced

**Hypothesis.** The "1:1 with master" port should issue one SQE per recv/send that epoll
issues as a syscall. Is that true op-for-op — and is the +17% large-object cost partly an
op-count regression rather than just per-op locality?

**Experiment.** Count io_uring SQEs by opcode (`io_uring:io_uring_submit_req` op_str) and
`io_uring_enter` syscalls, vs epoll's recvmsg/sendmsg, per transaction, at a fixed
sub-saturation rate. 4 KB RAM-hit (client I/O only) and 1 MB passthrough (origin read +
client write). The epoll path uses `recvmsg`/`sendmsg` (`UnixNetVConnection.cc:537,855`),
not readv/writev — so the syscall set is captured exactly.

**Result.**

| | reads | writes | total ops | actual syscalls |
|---|---|---|---|---|
| **4 KB hot** io_uring | 0.86 recv | 0.85 send | **1.71 SQE** | (batched, < 1.71) |
| 4 KB hot epoll | 1.95 recvmsg | 0.97 sendmsg | **2.93** | 2.93 |
| **1 MB pass** io_uring | 28.8 recv | **28.8 send** | 57.6 SQE | **18.2 `io_uring_enter`** |
| 1 MB pass epoll | 35.0 recvmsg | **17.5 sendmsg** | 52.6 | 52.6 |

**Conclusion.** Three distinct facts the loose CQE count had blurred:
- **At the syscall level io_uring wins decisively** — 1 MB passthrough: 18.2 `io_uring_enter`
  vs 52.6 syscalls (**2.9× fewer**); its 57.6 SQEs batch ~3.2-to-1. On the hot path it also
  does *fewer ops* (1.71 vs 2.93): epoll burns an extra recvmsg/req on the EAGAIN
  drain-probe that io_uring's "submit one recv and wait" avoids.
- **At the op level io_uring does ~10% more ops on the passthrough, and the increase is
  *sends*** (28.8 vs 17.5, +64%). The tell: io_uring's send/req (28.80) ≈ recv/req (28.81)
  — **one send per recv completion**, ~36 KB each; epoll coalesces ~2 reads into one ~60 KB
  send. Mechanism: each origin recv completion reenables the client write VIO, which fires
  `net_write_io` with just that one block available (`IOUringNetVConnection.cc:377` signals
  `READ_READY` after *every* recv); epoll's synchronous read loop pulls several blocks into
  the buffer before the write side runs, so its write batches them.
- **Why it costs:** each extra send is one extra CQE = one extra coroutine resume paying the
  H7 frame+ring footprint — so the ~11 un-coalesced sends/req are a real slice of the +17%
  large-object gap, *not* via syscalls (those are down) but via per-op coroutine cost. This
  is a 1:1-with-master-shaped lever (make the io_uring read accumulate before signalling,
  like epoll's drain loop) — see H12.

## H12 — Write-coalescing: cuts the op count but *raises* CPU (rejected)

**Hypothesis.** H11 found io_uring issues ~64% more sends than epoll (one send per recv
completion). Coalescing them — so the downstream write batches blocks like epoll's drain
loop does — should cut coroutine resumes and recover cycles on the large-object path.

**Experiment.** Make `_read` accumulate before signalling: on a *full* recv (more may be
buffered) loop and read again WITHOUT signalling `READ_READY`; signal only on a short read
(socket drained), `READ_COMPLETE`, or a full buffer (consumer must drain). This mirrors
`UnixNetVConnection`'s synchronous recv-until-short-read drain, so the tunnel forwards N
blocks at once and `_write` coalesces them. Op-count + interleaved fixed-rate cpu A/B on
the 1 MB passthrough; instr/req as the clean (low-noise) discriminator.

**Result.**

| | sends/req | total ops/req | cpu/1k med | instr/req |
|---|---|---|---|---|
| baseline (per-block sends) | 28.8 | 57.6 | 0.450 | ~1.345 M |
| coalesced | **16.1** | 44.9 | 0.459 | **~1.425 M (+6%)** |
| epoll (ref) | 17.5 | 52.6 | — | — |

The coalescing *works* — sends fall 28.8→16.1 (below epoll's 17.5), the tally flips from
single-block `SEND` to multi-block `SENDMSG`, total ops drop below epoll. **But cpu/1k rises
~2% and instr/req rises a clean, non-overlapping +6%** (reverting restores 1.36 M, proving
it's the change, not drift).

**Conclusion. Reject — and it's an instructive negative that *validates H6.*** Fewer ops did
not mean less CPU; the opposite. Because the **async batched write (H6) already amortizes the
send syscalls** (the 28.8 sends batch ~3:1 into `io_uring_enter`), coalescing removes
syscalls that were already nearly free while *adding* the cost of building big multi-block
`sendmsg` iovecs (clone reader, walk/consume N blocks) plus the read-accumulation loop. It
optimizes a cost H6 had already paid down. The simple per-block `prep_send` path is genuinely
cheap; keep it. (This also re-confirms H7's framing: the per-op cost is small — so cutting
ops buys little, and here it backfires.)

## Validation & recommendations

**Validation (combined doorbell + async-write change, current working tree):**
- 4/4 io_uring autests pass (Debug): `io_uring_connect`, `io_uring_netvc`,
  `io_uring_read` (256 KB body, multi-block write — exercises the async path),
  `io_uring_origin_timeout` (teardown with an op in flight — and the async write now
  *always* sets `_write_op`, so the close-while-write-in-flight path is exercised on
  every write, not just on EAGAIN).
- ASan `-F` (freelist off, so ASan sees every VC/frame free) load + connection churn +
  1 s keep-alive timeout: **clean** — no use-after-free / overflow / double-free over
  1.22 M requests.

**Recommendations.**
1. **Keep the cross-thread doorbell (H2).** It is a correctness fix for a real
   regression the io_uring branch introduced (cross-thread work stalls to the 60 ms
   heartbeat), it is provably perf-neutral, and it is the right way to be "fully
   io_uring without the eventfd". Follow-up: the io_uring build's *epoll fallback*
   (`enabled=0`) still lacks `thread->evfd` registration — restore `AsyncSignalEventIO`
   there for symmetry.
2. **Adopt the async batched write (H6)** — but knowingly, since it reverses EXP-1b.
   It removes the per-request `sendmsg`, is −1.8% cycles/req, and collapses the medium-
   object write tail; validated above. Keep the existing `-F`/ASan teardown test as the
   guard (the always-in-flight `_write_op` makes that path hotter).
3. **Keep `IOU_FRAME_IOV=16` (H1).** Confirmed optimal across sizes.
4. **Do not pursue the frame arena (H4)** — no measurable benefit at this scale.
5. The residual ~+2% cycles (H5) is locality in the coroutine `.actor` bodies + the
   ring; with the async write it is ~+0.8%. Beyond this, the only remaining lever is
   multishot recv + provided buffers (deferred — out of scope here).
6. **Do not chase the frame footprint (H7/H8/H10).** Three independent attempts on the
   residual all came up empty: huge pages can't reach the io_uring allocations and help
   nothing measurable (H8); shrinking the frame is a dead end (H10); embedding the frame
   in the VC is correct + clean but perf-neutral and costs per-connection memory (H10).
   The FramePool already neutralizes the frame cost. The small-object hot path is at
   cpu/1k parity and the **only** path to a clean io_uring *win* is reducing ops/req —
   i.e. the deferred advanced features (multishot recv, provided buffers), which attack
   the per-op CQE/resume structure that H9 identified as the real large-object cost.
   Everything 1:1-with-master that could be done here has been done.
