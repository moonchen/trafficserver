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
