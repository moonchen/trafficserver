# io_uring + coroutine net path — performance study

The single performance document for the io_uring/coroutine network path (branch
`io-uring-coroutine-wip`) versus the epoll baseline (master). All perf data and analysis
live here; `DECISIONS.md` is the companion that records *what was decided* (and points back
here for the *why*).

## How to read this

Organized around the **cost transitions** you actually want to reason about, with an explicit
**known / unknown** split, so you can see what is measured before choosing where to optimize.

- **§1 Cost model** — the one equation everything decomposes into.
- **§2 Transition A: syscall → io_uring** — how the submission/completion model moves cost.
- **§3 Transition B: stack → coroutine frame** — how moving per-op state off the stack moves cost.
- **§4 Other axes we have data for** — object size, environment, direction, cache, allocation, concurrency.
- **§5 Per-op cost catalog** — the concrete per-op numbers (real NIC).
- **§6 Known / unknown ledger** — every claim with evidence + confidence.
- **§7 Known unknowns** — the gaps that matter, named from where we stand.
- **§8 Optimization directions** — what the gaps point to.
- **Rig & method**, **Background**, then the **Experiment log** (the live evidence), and an
  **Appendix of ruled-out options** (tested-and-dominated, kept as one-liners so we don't re-try them).

**Confidence tags:** **[Known]** = measured, reproduced (≥3 reps or n≥1.8M-req windows),
mechanism understood; **[Thin]** = measured but under-powered (single environment / noisy
metric / n=1); **[Open]** = not measured.

**Two environments** (detail in *Rig & method*). **Loopback** charges ~0 for syscall-entry and
~0 for transmit → isolates userspace + copy. The **real NIC** (1 GbE to a separate host)
charges both. *Loopback was right about every CPU/cache/frame mechanic and wrong, in both
directions, about anything gated by syscalls or transmits* — so NIC-sensitive claims are
tagged with their NIC result, and loopback-only ones are flagged.

---

## §1 Cost model

Everything reduces to one equation:

    CPU/request ≈ (ops per request) × (mean cost per op)

**ops per request = bytes ÷ bytes-per-op**, and bytes-per-op is set by **coalescing**, which is
asymmetric:

- **Writes coalesce.** The whole response sits in the buffer; the sender picks the op size (and
  TSO coalesces further in the NIC). A 1 MiB cache hit goes out in ~2 sends of ~520 KB.
- **Reads cannot.** Inbound data arrives at line rate, so each read drains only what landed
  since the last one — and on a real 1500-MTU NIC that is ~1 MTU. **A 1 MiB upload becomes
  ~750 reads of ~1.4 KB.** (Loopback's 65536 MTU hides this — there the same read is ~29 ops;
  the real-NIC fragmentation is the truth, and it is the single biggest fact about bulk-transfer
  cost: **reads cost ~20× more CPU/byte than writes**.)

**cost per op splits three ways**, and the two transitions move *different* terms:

| term | what it is | moved by |
|---|---|---|
| **userspace** | coroutine-frame touch + resume/suspend + protocol / op-building | **both** (A adds the resume; B changes frame locality) |
| **kernel / syscall** | per-op copy (recvmsg/sendmsg) + syscall entry | **Transition A** — io_uring batches the *entry*; the per-byte copy is unchanged |
| **softirq** | NIC RX/TX completion (per byte / per packet) | neither — engine-independent, per-byte; **absent on loopback** |

The whole game is reading that split: **io_uring's wins and losses live in the *userspace*
term and in *instruction count*; the *kernel transfer* (system + softirq) is essentially
engine-flat for the same bytes** [§5]. A userspace event-model change can only move the
userspace slice — large when ops are many and small, negligible when ops are few and big.

---

## §2 Transition A: syscall → io_uring

**Mechanically:** epoll = readiness (`epoll_wait`) + one syscall per op (recvmsg/sendmsg), with
a userspace drain loop pulling several blocks per wakeup. io_uring = queue SQEs; one
`io_uring_enter` (`submit_and_wait`) per event-loop iteration drains *all* ready CQEs and
submits *all* queued SQEs; each completion **resumes a coroutine**. Single-block transfers use
`recv`/`send`, multi-block use `recvmsg`/`sendmsg`.

**Known:**
- **Syscall batching wins where syscalls cost.** Small-object hot path: 1.35 `io_uring_enter`/req
  vs epoll's ~3 syscalls → **−6% total CPU on the NIC** (it was *parity* on loopback, where a
  syscall is free). [Known — A6, §5]
- **io_uring wins the read path: −16% user CPU, stable across 6 reps.** epoll fires ~1431
  recvmsg/req but only ~747 return data (~684 wasted EAGAIN edge-retriggers); io_uring issues
  only the productive recvs, and uses the lighter `recv` (no msghdr) where epoll always pays
  recvmsg. [Known — §5, A5]
- **`send()` < `sendmsg()` by ~480 instr** (the kernel skips `copy_msghdr` + `import_iovec`),
  NIC-independent. io_uring's per-block path already uses `send`. [Known — A6]
- **The async batched write removes the per-request sendmsg** (it rides `submit_and_wait`):
  `sendmsg` 0.98→0/req, net syscalls ~halve, −1.8% cycles, IPC 1.368→1.400, and the 64 KB write
  tail collapses (~550 ms → ~16 ms). The benefit *grows* on the NIC. [Known — A4]
- **Op count dominates total cost, and coalescing helps io_uring more than epoll.** Small-block
  write: coalescing cuts instr/req epoll −11%, **io_uring −45%** — each un-coalesced io_uring
  send is a coroutine resume + enter; epoll loops several sends inside one wakeup. At big block
  sizes (cache hit) coalescing is moot (≤8%, copy-dominated). [Known — §5]
- **Large-object liability: io_uring's un-coalesced "one send per recv" does ~2× epoll's
  transmits** → +5–8% on the NIC (real driver `xmit` + TX-softirq), +17% on loopback (per-op
  resume). The one place io_uring is genuinely behind on real hardware. [Known — A5, A6]
- **Cross-thread doorbell regression + fix.** The branch dropped `thread->evfd` registration
  (compile-time gated), stalling cross-thread work to the 60 ms heartbeat; a multishot poll on
  `thread->evfd` restores it (p99 62 ms → 2.2 ms, perf-neutral). [Known — A2]

**Open / thin:**
- **A write-side send batch that preserves the read↔write interleave** — the actual fix for the
  large-object liability (read-side coalescing is *ruled out*, see appendix; this would batch
  *sends* without serializing the connection). Not built. [Open]
- **Multishot recv + provided buffers** — the only structural lever on the read side
  (the ~750 reads/MiB and the ring footprint). Open question gating it: does line-rate arrival
  still cap each completion at ~1 MTU, or can a provided-buffer ring carry more? [Open]
- **Syscall-batching win at CPU saturation** — the 1 GbE link caps load below CPU saturation;
  the magnitude of the win at a CPU-bound point is unmeasured. [Thin]

---

## §3 Transition B: stack → coroutine frame

**Mechanically:** master keeps the iovec array + msghdr as **stack locals** in
`net_read_io`/`load_buffer_and_write` — reused at a fixed, cache-warm address every call.
io_uring keeps them in the **coroutine frame**: a heap block, pooled (thread-local LIFO
`FramePool`), pinned across the await. `IOU_FRAME_IOV=16` sizes it at ~528 B.

**Known:**
- **The frame pool is load-bearing.** With it off, io_uring's frames hit the general allocator →
  **+8–17% CPU vs master** and the tail collapses; that is the per-op cost of 2 unpooled
  frames/req. The recovered win is primarily an *allocation-instruction* effect (fewer
  malloc/free/madvise), not chiefly a TLB effect. [Known — Background, 12-cell matrix]
- **Frame *size* is the dominant frame risk, not op-count coverage.** The original +21% was
  largely the 16 KB frame (`IOU_FRAME_IOV=1024`); shrinking to 16 fixed it. iov=16 is the flat
  optimum across object sizes; "larger transfers need a larger iovec" is **wrong** (large
  transfers are copy-bound; op-count cost vanishes). [Known — A1]
- **The post-fix residual is locality, not control flow.** io_uring +1% instr / +2% cycles on
  loopback; the gap is +27% cache / +28% dTLB / +17% branch-miss, in the two `.actor` bodies +
  `submit_and_wait`. Precise leaf attribution: **memory-footprint** — LLC +79%, dTLB-walk +59%,
  **L1 ≈ 0** (cold-line/capacity at the frame + rings); the coroutine resume jump is
  **BTB-predicted, not a branch-miss source** (the intuitive culprit is refuted). [Known — A3]

**Bottom line:** the frame cost is **already neutralized** (FramePool + iov=16). It is a ~2%
loopback locality residual that the NIC's syscall-batching win more than covers. **The frame is
not a lever** — every attempt to squeeze it further was null (see appendix: arena, shrink,
frame-in-VC, huge pages).

**Open / thin:**
- **Memory + locality at 10k+ connections.** The frame is pooled per *active* op, but the
  per-VC + ring footprint at high conn counts is unmeasured, and the prototype pool never frees
  (cap 8192/size/thread) — a bounded/watermarked production allocator could re-introduce
  malloc/free under fluctuating conns. The locality residual is explicitly a *scaling* risk. [Open]
- **Locality under a busier i-cache** (TLS, plugins) — measured only on a lean plaintext path. [Thin]

---

## §4 Other axes we have data for

Beyond the two transitions, these axes were exercised; each is "what we know + where the gap is."

| axis | what the data says | evidence | gap |
|---|---|---|---|
| **Object size** | op-overhead matters at small/medium (4–64 KB), vanishes when copy-bound (≥1 MB). iov sensitivity peaks at 64 KB (U-curve), flat by 1 MB. | A1, A6, §5 | nothing swept between 64 KB–1 MB on the NIC |
| **Environment** (loopback vs NIC) | loopback under-charges syscalls *and* transmits; flips io_uring's verdict from "parity" to "small-object win / large-object loss". Also under-counts read ops (big MTU). | A6, all NV | only 1 GbE; **10G+ and CPU-saturated NIC unmeasured** |
| **Direction** (read vs write) | reads can't coalesce → ~750 ops/MiB on the NIC, ~20× the CPU/byte of writes. | §5 | full-duplex / simultaneous bidirectional load unmeasured |
| **Cache hit vs passthrough** | hit = write-only, ~2 sends, parity-class; passthrough = origin read + client write, where the large-object op-structure gap lives. | A5, A6 | **real disk-cache I/O** unmeasured (only RAM hit + passthrough) |
| **Sync vs async write** | async batched send wins post-fix (A4). | A4 | — (live) |
| **Coalesce vs not** | coalescing helps io_uring ≫ epoll on writes; read-side coalescing loses (appendix). | §5, A6 | — (live) |
| **Allocation strategy** | pool = load-bearing; off = +8–17%; arena / frame-in-VC / huge-page all null. | Background, B-appendix | bounded allocator at 10k+ conns unmeasured |
| **malloc (glibc vs jemalloc)** | jemalloc helps *master* more than io_uring (io_uring already bypasses malloc for frames + ATS freelists). | 12-cell matrix | — |
| **Connection count / cross-thread** | conns ≤ 600 measured; cross-thread doorbell fixed (A2). | A2, Background | **10k+ conns** (memory + locality), high churn |

---

## §5 Per-op cost catalog (real NIC, 1 GbE → hawaii)

The most direct decomposition: each op split into **userspace / kernel / softirq**, from the
6-op isolation (experiment A7; generator-plugin workloads, no origin/disk, cgroup
`user_usec`/`system_usec` split, 6 reps; instr/req stable ±1%, softirq noisy ±40%).

| op (serving 1 MiB) | ops/req | KB/op | user µs | sys µs | softirq µs | **instr/req** |
|---|---|---|---|---|---|---|
| READ epoll `recvmsg` | 747 | 1.4 | 1566 | 2979 | 1779 | 13.74 M |
| READ io_uring `recv` | 747 | 1.4 | **1320** | 2818 | 2353\* | 13.52 M |
| WRITE-small epoll `sendmsg` (coalesce) | 33 | 31 | 219 | 326 | 378 | 0.649 M |
| WRITE-small io_uring `sendmsg` (coalesce) | 33 | 31 | 205 | 331 | 419 | 0.677 M |
| WRITE-small io_uring `send` (no-coalesce) | 93 | 11 | 275 | 392 | 356 | 1.241 M |
| WRITE-big, cache hit (~520 KB blocks) — any engine | ~2 | ~520 | ~70 | ~260 | ~310 | 0.204–0.221 M |

\* read softirq is within the ±40% noise band (epoll 1397–2695, io_uring 1080–3201); it does
**not** separate the engines. (The dominated epoll `send`-no-coalesce row is folded into the
appendix.) NV anchors (per request, mixed): 4 KB hot — io_uring 0.0281 vs epoll 0.0299 cpu/1k
(**−6%**); 1 MB passthrough — io_uring 1.98 vs epoll 1.85 cpu/1k (**+5–8%**).

**What the catalog shows (the cost model, concretely):**
1. **Op count = total cost.** The *same* 1 MiB is 0.20 M / 0.65 M / 13.7 M instr depending only
   on how many ops it's chopped into (2 big sends → 33 small sends → 747 MTU reads). Per-op cost
   is ~constant; **bytes-per-op is the lever.**
2. **Reads cost ~20× more CPU/byte than writes** — the read can't coalesce (line-rate arrival).
3. **Coalescing helps io_uring far more than epoll** (small-block write instr: io_uring −45%,
   epoll −11%); at big-block (cache hit) it's moot.
4. **The split localizes everything:** io_uring's deltas are in **user CPU + instructions**;
   **system + softirq are per-byte and engine-flat**.

---

## §6 Known / unknown ledger

| claim | transition / axis | evidence | confidence |
|---|---|---|---|
| Syscall batching wins small objects on the NIC (−6%) | A | A6, §5 | **Known** |
| io_uring wins reads (−16% user; avoids epoll EAGAIN waste) | A | §5, A5 | **Known** |
| `send()` < `sendmsg()` (~480 instr) | A | A6 | **Known** |
| Async batched write removes per-req sendmsg (−1.8% cyc) | A | A4 | **Known** |
| Coalescing helps io_uring ≫ epoll; op count is the lever | A | §5 | **Known** |
| Large-object un-coalesced sends: +5–8% NIC liability | A | A5, A6 | **Known** |
| Cross-thread doorbell regression + multishot-poll fix | A | A2 | **Known** |
| Frame pool is load-bearing (off = +8–17%) | B | Background | **Known** |
| iov=16 optimal; frame *size* is the only frame risk | B | A1 | **Known** |
| Residual = memory-footprint locality, not control flow | B | A3 | **Known** |
| Reads can't coalesce → ~750 ops/MiB on a real NIC | A / direction | §5 | **Known** |
| Write-side batch preserving read↔write interleave | A | — | **Open** |
| Multishot recv + provided buffers (read op count, copy) | A/B | — | **Open** |
| TLS path (per-record blocks → coalescing relevant) | A | — | **Open** |
| 10k-conn memory + bounded allocator at scale | B | VERDICT scope caveat | **Open** |
| Syscall-batching win at CPU saturation | A | — | **Thin** |
| HTTP/2, disk-cache I/O, NUMA, 10G+, error/churn paths | mixed | — | **Open** |

---

## §7 Known unknowns — the gaps that matter

Named from where we stand. Ordered by how much they could change the verdict.

1. **TLS.** Everything is plaintext. TLS produces many small per-record write blocks, which puts
   us squarely in the regime where write-coalescing and Transition A's op-count term dominate —
   and where io_uring's "coalescing helps it more" likely shows up as a *win*, not parity. Also
   the async-SSL engine interaction is untested. **The single biggest unknown for a real verdict.**
2. **Scale: 10k+ connections.** Per-VC + ring + pooled-frame memory, and the H7 locality residual
   that is explicitly a scaling risk. The prototype pool never frees (cap 8192/size/thread,
   ~100 MB/thread at 100k conns); a bounded/watermarked production allocator is the most likely
   way the frame-pool win under-delivers under fluctuating conns (a VERDICT scope caveat we never
   closed).
3. **CPU-saturated NIC operating point.** We ran *below* saturation (1 GbE caps offered load). The
   syscall-batching win (−6% small) is measured at low utilization; its magnitude when the box is
   CPU-bound — the operating point that matters for capacity — is unmeasured.
4. **Multishot recv + provided buffers.** The deferred io_uring features. They are the *only*
   structural attack on the read side's ~750 ops/MiB and the only path to a different copy story
   (zero-copy / kernel-chosen buffers). Open question: does line-rate arrival still force
   ~1-MTU completions even with a provided-buffer ring?
5. **The write-side send-batch lever's actual cost.** The proposed fix for the large-object
   liability (batch sends without serializing the read loop). Unbuilt, so its win is hypothetical.
6. **HTTP/2.** Multiplexing many streams over one connection changes the op pattern (interleaved
   small frames) and the buffering — a different op-count regime than HTTP/1.1 keep-alive.
7. **Real disk-cache I/O.** Only RAM-hit and origin-passthrough are measured. The disk path uses
   thread-mode AIO and cross-thread completions (where the A2 doorbell matters) — unmeasured cost.
8. **Larger MTU / 10G+ NIC.** Read fragmentation (§1) is MTU-gated; jumbo frames or 10G change
   bytes-per-read and per-transmit cost, possibly shrinking the read-side gap.
9. **NUMA / multi-socket.** Single-socket 12900K only; ring/frame/buffer locality across NUMA
   nodes is untested.
10. **Error, teardown, and churn paths.** Only the happy path's *CPU* is measured. RST / timeout /
    half-close correctness is tested (and accept/connect are on io_uring), but per-connection
    setup/teardown CPU at high churn, and behavior under packet loss / retransmit, are not.

---

## §8 Optimization directions

The known results close off several tempting directions and point at two real ones.

**Pursue — the open levers (both on Transition A's op-count term):**
1. **Write-side send batching that preserves the read↔write interleave.** The large-object
   liability is io_uring's one-send-per-recv (A5). Read-side coalescing fixes the symptom but
   halves op concurrency (appendix). A batch on the *write* side — accumulate ready blocks into
   one send without stalling the read loop — is the untried lever. [Open]
2. **Multishot recv + provided buffers.** The only structural attack on the read side's
   ~750 ops/MiB (and the ring/frame footprint). Whether line-rate arrival still caps a completion
   at ~1 MTU is the open question that gates it. [Open]

**Do not pursue — closed by the evidence (see appendix for each):** the coroutine frame
(neutralized; arena / shrink / huge-pages / frame-in-VC all null), read-side write-coalescing
(net loss on both media), and bigger MIOBuffer blocks (CQE/req is set by backpressure, not block
size).

**Measure before shipping — the §7 unknowns that gate the default:** TLS, 10k-conn memory, and
NIC behavior at CPU saturation. Until these land, gate behind `net.io_uring.enabled` (done),
default off.

**Net for shipping:** on a real NIC, io_uring is a **net win on the dominant small-object /
keep-alive traffic** (−6%, + a 2–3× p99 tail improvement) and a **bounded loss on large
streaming bodies** (+5–8%); loopback's "parity" undersold both halves.

---

## Rig & method

### Loopback environment
- **Box:** i9-12900K (8 P-cores + 8 E-cores), Ubuntu 24.04 HWE, kernel 6.17, liburing 2.4.
  During runs: `performance` governor, turbo **off**, `perf_event_paranoid=-1`.
- **Pinning:** ATS in a cgroup-v2 cpuset (P-cores; taskset is insufficient — hwloc rebinds
  ET_NET threads); client (`wrk2`) on the remaining cores. 4 ET_NET threads, 1 accept thread.
- **Gold metric:** `cpu/1k-req` = cgroup `cpu.stat` `usage_usec` ÷ requests (ATS user+sys only;
  softirq and client excluded) — a clean per-request efficiency signal independent of the
  bottleneck.
- **Workload:** `wrk2` open-loop constant rate, HTTP/1.1 keep-alive, reverse-proxy + remap,
  100% RAM-cache HIT (validated `RAM% = 100`). Same Release `-O3 -fno-omit-frame-pointer` binary
  with `net.io_uring.enabled` toggled 0/1 — the only variable is the net path.

### Real-NIC environment
- **Server:** ATS on the i9 over `enp6s0` (atlantic, **1 GbE**). **Client:** `hawaii`, an M1 Mac
  Mini, `wrk` — a genuine second host, so writes traverse the real driver TX path. (Localhost
  can't test this — the kernel short-circuits local addresses to loopback before any driver.)
- **The 1 GbE link caps throughput** (~27k rps at 4 KB, ~115 rps at 1 MB), so the box runs
  *below* CPU saturation. Per-request ratios (`cpu/1k`, `instr/req`, ops/req) stay valid.
- **Two CPU accountings:** `proc cpu/1k` = ATS cgroup CPU (incl. the driver `xmit` in send-syscall
  context); `softirq cpu/1k` = `/proc/stat` softirq ÷ req (the NIC TX/RX completion the cgroup
  misses; noisy → corroborating, not load-bearing). The 6-op rig (A7) additionally splits the
  cgroup into `user_usec` / `system_usec`.
- Harness is out-of-tree at `~/work/io-uring-coro-bench` (`measure-nic2.sh`, `measure-6op.sh`,
  `setup-box.sh`); raw cells in `findings/*.txt` + `SIXOP.csv`.

## Background: +21% → parity (the five fixes)

The io_uring net path was once **+20.9% cpu/req** vs epoll with a collapsing p99 tail. Five
fixes brought it to loopback parity, ranked by impact:
1. **Shrink the inline iovec `NET_MAX_IOV`(1024 ⇒ 16 KB) → 16** — the 16 KB array lived in the
   *heap coroutine frame* pinned across the await, where master keeps it as a cache-warm *stack*
   local (~12 of the ~20 points; instr/req 71k→59k, dTLB 14.3→8.7).
2. **Block directly in `io_uring_submit_and_wait`** instead of bridging completions through an
   eventfd into `epoll_wait` (~3 points; drops `epoll_wait` + eventfd read per req).
3. **Async batched write** (superseded the original sync write — see A4) (~3 points).
4. **Single-buffer `recv`/`send`** for the 1-block case (lighter kernel than recvmsg/sendmsg).
5. **Unregister the dead completion eventfd** (~1 point).

**Anchors.** Loopback (n=5, 4 KB, 120k rps): master 0.0139 vs io_uring 0.0140–0.0141 = **+0.7–1.4%**,
p99 ~2.1 ms (and ~2–3× *better* tail than epoll across freelist modes). Real NIC (4 KB, 1 GbE):
io_uring 0.0281 vs epoll 0.0299 = **−6%**. The harness reproduces both, so the experiments stand
on a validated baseline.

---

## Experiment log (the live evidence)

Each entry: hypothesis → key data → conclusion. Tagged by transition. Dead-end experiments are
in the appendix, not here. *Label map for legacy references (`DECISIONS.md`, prior notes):
A1=H1, A2=H2, A3=H5+H7, A4=H6, A5=H9+H11, A6=NV1–4, A7=the 6-op isolation.*

### A1 — iovec size vs transfer size [Transition B] [Known]
Sweep `IOU_FRAME_IOV ∈ {1,4,16,64,256,1024}` × {64 KB, 1 MB, 8 MB}, Δ vs the (iovec-independent)
epoll reference:

| iov | 64 KB | 1 MB | 8 MB |
|---|---|---|---|
| 1 | **+10.5%** | +1.1% | −1.5% |
| 4–64 | **−2.9%** (optimum) | ±1% | ±2% |
| 1024 | **+3.8%** | +2.0% | −1.0% |

A clean U-curve at 64 KB (too few iovecs → extra ops; too large → 16 KB frame bloat); flat by
1 MB (copy-bound — even iov=1 is within noise). **iov=16 sits in the flat optimum** and is far
from both costly extremes. The "larger transfers need a larger iovec" intuition is wrong; the
real risk is the *large* frame.

### A2 — cross-thread wakeup doorbell [Transition A] [Known] — *actionable correctness fix*
`initialize_thread_for_net` chose `IOUringEventIO` vs `AsyncSignalEventIO` at **compile time**
(`#if TS_USE_LINUX_IO_URING`), so the io_uring build never registered `thread->evfd` (the
cross-thread wakeup fd). A thread blocked in `submit_and_wait`/`epoll_wait` could not be woken by
another thread → such work stalled to the 60 ms heartbeat. Plain HTTP is unaffected (default
`aio.mode=auto` keeps connection work thread-local), which hid it.

| net path (forced `aio.mode=thread`, disk cache, conns=4) | p50 | p99 |
|---|---|---|
| epoll (io_uring build, enabled=0) | 1.13 ms | **62.1 ms** |
| io_uring, no doorbell | 1.11 ms | **61.6 ms** |
| io_uring, **doorbell** | 1.07 ms | **2.21 ms** |

**Fix:** arm `io_uring_prep_poll_multishot` on `thread->evfd` in the ring (re-armed on
`!IORING_CQE_F_MORE`) — the io_uring-native `AsyncSignalEventIO`. **p99 62 → 2.2 ms,
perf-neutral** (the poll only completes when rung). Restore `AsyncSignalEventIO` on the epoll
fallback too.

### A3 — the residual: locality / footprint [Transition B] [Known]
Clean within-session n=3 A/B (same binary toggled, ~1.8M req/window):

| /req | epoll | io_uring | Δ |
|---|---|---|---|
| instructions | 58,055 | 58,637 | +1.0% |
| cycles | 41,551 | 42,386 | +2.0% |
| cache-misses | 76.1 | 96.7 | +27% |
| dTLB-misses | 7.42 | 9.48 | +28% |
| branch-misses | 76.4 | 89.1 | +17% |

Precise/leaf (PEBS): **LLC +79%, dTLB-walk +59%, L1 ≈ 0** — a cold-line/capacity cost at
`_read.actor` (the 528 B frame) + `submit_and_wait` (the rings), **not** L1 thrash and **not**
control-flow (the resume jump is BTB-predicted, so it is not a branch-miss source — the intuitive
culprit is refuted). Symbol diff: io_uring adds `_read.actor` +1.55%, `_write.actor` +1.07%,
`submit_and_wait` +0.77%; removes epoll poll-callback + syscall-entry machinery. The honest floor
of the current design: ~2% cycles, locality-bound, no single hot spot. **On the NIC this ~2% loss
inverts into the −6% small-object win** (A6).

### A4 — async batched write [Transition A] [Known] — *actionable optimization*
Sync `sendmsg` vs a pure async io_uring send riding the batched `submit_and_wait`:

| /req | sync `sendmsg` | pure async |
|---|---|---|
| `sendmsg` syscall | 0.98 | **0** |
| total net syscalls | ~1.33 | **~0.52** |
| cycles/req | 42,671 | **41,897 (−1.8%)** |
| IPC | 1.368 | **1.400** |
| 64 KB write p99 | 240–600 ms | **3–32 ms** |

The send SQE rides the one `submit_and_wait` per loop, so at load many sends batch into one
`io_uring_enter` and the per-request `sendmsg` disappears. cpu/1k −2.2% (4 KB) / −2.9% (64 KB).
Combined with A2 vs epoll: 4 KB +0.7% (noise), **64 KB −4.3%**, cache-MISS 1 MB +0.1%. (This
*reversed* the earlier "sync is cheaper" finding — that held only before the frame was small
enough to make the resume nearly free; see appendix.)

### A5 — large-object op structure [Transition A] [Known] — *the open liability*
Op counts per transaction (fixed sub-saturation rate):

| | reads | writes | total ops | syscalls |
|---|---|---|---|---|
| 4 KB hot, io_uring | 0.86 recv | 0.85 send | 1.71 SQE | batched (<1.71) |
| 4 KB hot, epoll | 1.95 recvmsg | 0.97 sendmsg | 2.93 | 2.93 |
| 1 MB pass, io_uring | 28.8 recv | **28.8 send** | 57.6 SQE | **18.2 `io_uring_enter`** |
| 1 MB pass, epoll | 35.0 recvmsg | **17.5 sendmsg** | 52.6 | 52.6 |

Three facts: (1) **io_uring wins syscalls decisively** (18.2 enter vs 52.6 = 2.9× fewer; and on
the hot path fewer ops — epoll burns an EAGAIN drain-probe recvmsg io_uring avoids). (2) **At the
op level io_uring does ~10% more, all sends** — send/req ≈ recv/req means *one send per recv
completion* (`READ_READY` signalled after every recv), where epoll's drain loop coalesces ~2
reads/send. (3) **Each extra send is one extra coroutine resume** — on loopback a per-op cost
(+17%); on the NIC a real driver `xmit` + TX-softirq (A6). A bigger MIOBuffer block does *not*
help: CQE/req is immovable (67.6→67.0 across 8 KB→256 KB→+2 MB SO_RCVBUF) — backpressure, not
block size, sets the recv count (appendix).

### A6 — real-NIC validation [Transition A] [Known]
Same FP binary toggled, ATS over `enp6s0` (1 GbE) → hawaii. Medians of 3 interleaved rounds.

**NV1 — headline:**

| workload | arm | proc cpu/1k | softirq | total | instr/req |
|---|---|---|---|---|---|
| 4 KB hot | io_uring | 0.0173 | 0.0108 | **0.0281** | 61,181 |
| | epoll | 0.0185 | 0.0114 | **0.0299** | 60,426 |
| 1 MB pass | io_uring | 0.611 | 1.369 | 1.98 | 1,142 K |
| | epoll | 0.582 | 1.270 | 1.85 | 1,036 K |

Small object **−6% (io_uring wins)** — was *parity* on loopback; the win is op batching
(1.35 enter/req vs ~3 syscalls) where a syscall has real cost. Large object **+5–8%** — was
+17% proc on loopback with *zero* transmit cost; on the NIC the proc gap shrinks but a real
**softirq/`xmit`** cost appears because io_uring's un-coalesced sends (A5) do ~2× epoll's
transmits.

**NV2 — send strategy isolated (epoll-only A/B, `instr/req`):**

| epoll write strategy | loopback | real NIC |
|---|---|---|
| coalesce + `sendmsg` (master default) | 1,354 K | **1,028 K (cheapest)** |
| no-coalesce + `send()` | **1,334 K (cheapest)** | 1,064 K |

`send()` < `sendmsg()` by ~480 instr on *both* media (NIC-independent — the kernel skips
`copy_msghdr`/`import_iovec`). But **the coalescing verdict flips sign**: a wash on loopback (no
transmit cost), genuinely cheapest on the NIC (each transmit carries a real driver `xmit`). This
is exactly why master coalesces — and why io_uring's per-block streaming is a NIC liability.

### A7 — per-op cost isolation [both transitions] [Known]
The 6-op matrix that produced §5. Origin-free + disk-free via the `generator` plugin: cache-hit
GET = pure send from RAM; `/nocache/` GET = regenerated through an in-memory PluginVC (32 KiB
blocks, makes coalescing engage); `POST 1 MiB` = generator drains the body so the only 1 MiB
socket op is the inbound recv. cgroup `user_usec`/`system_usec` split + softirq + perf opcode
mix; ATS on an exclusive cpuset partition, NIC IRQs isolated, 6 reps. The catalog and its four
conclusions are in §5; the headline is the read/write asymmetry (reads ~750 ops/MiB) and that
io_uring's deltas live in **user CPU + instructions**, not the kernel transfer.

---

## Validation

Combined doorbell (A2) + async-write (A4) change, current working tree:
- 4/4 io_uring autests pass (Debug): `io_uring_connect`, `io_uring_netvc`, `io_uring_read`
  (256 KB body, multi-block — exercises the async path), `io_uring_origin_timeout` (teardown with
  an op in flight; the async write always sets `_write_op`, so close-while-write-in-flight is
  exercised every write).
- ASan `-F` (freelist off → every VC/frame free visible) load + connection churn + 1 s keep-alive
  timeout: **clean** over 1.22 M requests (no UAF / overflow / double-free).

---

## Appendix: ruled out — tested and dominated

Kept as one-liners so we don't re-investigate them. Each was measured; each is dominated by a
better option already in the design (or is null). Raw data in `~/work/io-uring-coro-bench/findings/`.

**Transition A (op / syscall):**
- **Read-side write-coalescing** (accumulate reads before signalling, epoll-style). Cuts sends
  28.8→16.1/req (below epoll) but **+6% instr/req loopback, +12% cpu on the NIC** — the async
  write (A4) already amortized the send syscalls, so coalescing strips near-free syscalls while
  adding a multi-block `sendmsg` scatter-gather import; and it serializes each connection into a
  read-burst/write-burst ping-pong that **halves in-flight op concurrency** (SQE-per-enter 97→53)
  → more event-loop iterations than the saved sends are worth. *Dominated by per-block sends; the
  real fix is a write-side batch that preserves the interleave (§8).*
- **Opportunistic sync recv** (MSG_DONTWAIT recvmsg, fall back to io_uring on EAGAIN). 0.0170
  (worse) — a keep-alive read is a genuine wait, so the probe is a wasted EAGAIN syscall. *Read
  stays pure io_uring.*
- **Sync write** (the original opportunistic `sendmsg`). −1.2% only *before* the frame shrink;
  once the resume was cheap, async (A4) won and collapsed the write tail. *Superseded by A4.*
- **`sendmsg` without coalescing.** Pareto-dominated: 1,077 K instr on the NIC vs coalesce+sendmsg
  1,028 K and no-coalesce+send 1,064 K — you pay the msghdr import *and* skip coalescing.
- **Bigger MIOBuffer block** (8 KB→256 KB, +2 MB SO_RCVBUF). CQE/req immovable (67.6→67.0) —
  backpressure, not block size, sets the recv count. *Not a lever.*
- **SQPOLL.** Removes `io_uring_enter` entirely but dedicates a kernel poller core — the wrong
  trade for cpu/req. *Characterized, not adopted.*
- **Completion eventfd → `epoll_wait` bridge.** Pure indirection (io_uring layered on epoll);
  removed in the baseline fixes.

**Transition B (frame / memory):**
- **iovec extremes.** iov=1 (+10.5% at 64 KB, extra ops) and iov=1024 (+3.8% at 64 KB / +2% at
  1 MB, 16 KB frame bloat). *Dominated by iov=16 (A1).*
- **Frame contiguity (slab arena).** ≈ scattered LIFO freelist (±1%, noise) — the frame is small
  (~300–528 B) and LIFO reuse keeps it resident. *Null.*
- **Shrink `IOU_FRAME_IOV` 16→8.** Dead end — the cost is the *allocation*, not the byte count;
  below 16 you lose op-coverage (A1) for no locality gain. *Null.*
- **Frame-in-VC** (embed `_read_frame`/`_write_frame` in the VC, drop the pool). Correct + clean
  but **−0.5% (within noise)** — the pool already keeps the frame hot — and costs **1.28 KB on
  every VC** (worse memory scaling for idle keep-alives). *Keep the pool.*
- **Huge pages.** THP / glibc-`malloc.hugetlb` can't reach ATS's `ink_freelist`/brk allocations
  (`AnonHugePages=0`); the working ATS hugetlb knob backs only the shared iobuffer arena (lowers
  both arms). dTLB residual is <1% cpu anyway. *Not a lever.*
