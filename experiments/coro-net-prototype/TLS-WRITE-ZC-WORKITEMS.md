# TLS write-path zero-copy — work items to explore & benchmark

Forward-looking work items from the 2026-07-05 design discussion on making the
TLS send path zero-copy-efficient at *any* object size / client speed, without
the operator having to hand-tune `ssl.write_buffer_water_mark`.

**Read first for context:**
- `PERF-RESULTS-2026-07-04-tls.md` — the ladder + the "Why the arena regresses
  under TLS" root-cause subsection (the finding these items build on).
- `PERF-RESULTS-2026-06-28.md` — the plain-HTTP arena win these want to reach under TLS.

Each item below is self-contained: a fresh session can take one, read the
shared method appendix at the bottom, and run it. Items are ordered; **WI-1 is a
gate that can obsolete WI-3 — do it first.**

---

## The problem, decomposed

The `ssl.write_buffer_water_mark` knob currently conflates two independent things:

1. **Send granularity** — the ciphertext staging buffer (`_write_buf`) is a chain
   of blocks sized from the watermark, and the io_uring `_write` path issues **one
   `send_zc_fixed` per contiguous registered run**. Arena LIFO pops are
   non-adjacent, so a run ≈ one block → one send per block. At wm=256K a ~1 MiB
   TLS response is ~4 registered sends + a sub-threshold tail that falls back to a
   **plain copy** (~185 KB/req of the memcpy the arena exists to remove). Bigger
   blocks → fewer sends, no tail. Granularity wants blocks **as big as the
   remaining response** (up to the arena's top class).
2. **Staging depth** — how far `SSL_write` runs ahead of the socket. Deep staging
   = more pinned ciphertext per connection (memory) and looser backpressure /
   more encrypt-ahead wasted on aborts. Depth wants to be **as shallow as the
   client's drain rate allows**.

Static watermark can't satisfy both: 256K is right for depth on a slow client but
fragments sends; 1M is right for granularity but over-stages for slow clients.

**Measured today (root-cause session, one BoringSSL binary, NIC):** at wm=256K
arena ≈ parity with anonymous `send_zc`; at wm=1M arena beats the wm=1M anon cell
by ~**−11.9%** cpu/1k (n=2, disjoint, sys/1k roughly halved, p50 improved). The
plain-HTTP arena win (−13.3% same-session) never had the granularity problem — the
cache Doc is one contiguous block.

**Structural ceiling to keep in mind:** under TLS, ZC removes only the
ciphertext→socket copy; the AES pass already touches every byte. TLS ZC is a
smaller win than plain-HTTP ZC by nature and therefore more sensitive to a clean
send structure — which is why these items matter.

**The unifying target policy (what WI-3+WI-4 converge to):**
```
block_size = clamp( min(drain_rate × τ, remaining_response), 64K, arena_top_class )
```
- `remaining_response` from `vio.nbytes` (WI-3) — never stage past the response end.
- `drain_rate × τ` from the F_NOTIF completion stream (WI-4), τ ≈ 50–100 ms — bounds
  depth to the client's actual rate.
- Fast client + big object → big blocks (the wm=1M win); slow client → small blocks
  (bounded memory + tight backpressure); small object → never fills (moot).
This should **match-or-beat both static watermarks in essentially all cases** —
the headline hypothesis to prove.

---

## WI-1 — Kernel spike: gathered registered zero-copy send  ⚠️ DO FIRST (gate)

**Goal.** Determine whether a *single* io_uring send op can BOTH gather multiple
non-adjacent buffers AND use registered/fixed buffers (zero-copy, no per-send
pin). If yes, the per-block send split disappears at the source, block size stops
mattering for send structure, and **WI-3 becomes unnecessary** — the watermark
collapses to a pure depth knob (WI-4 alone).

**Why.** The two current ops each have half of what we want:
- anonymous `send_zc` = `sendmsg_zc` with an iovec → **gather yes**, pin-avoid **no**.
- arena `send_zc_fixed` = single registered buffer → gather **no**, pin-avoid **yes**.
We want **gather + pin-avoid** in one op. Candidate mechanisms:
- (i) `sendmsg_zc` + `IORING_RECVSEND_FIXED_BUF` — iovec of registered buffers.
- (ii) send **bundle** (`IORING_RECVSEND_BUNDLE`) of registered buffers — one send
  consumes multiple pre-posted provided buffers FIFO (batching indirection, not
  the kernel choosing data; pairs with WI-4's streaming staging).
- (iii) `IORING_SEND_VECTORIZED` (iovec form of the light send op) + fixed.
All arena blocks share one registered region (`buf_index 0`), so a gather over
non-abutting arena blocks is expressible *if the kernel accepts the combination*.

**Prerequisite — liburing bump.** The box runs kernel **6.17** (new; likely
supports all three) but the installed **liburing is 2.3 (2022)** and the libc
`io_uring.h` exposes only `FIXED_BUF`/`POLL_FIRST` — no `BUNDLE`, no
`SEND_VECTORIZED`. The whole ATS io_uring port builds against 2.3. **Step 0: build
current liburing (~2.9) in a scratch prefix** and spike against that; do NOT bump
the ATS build's liburing yet (that's a follow-on if the spike wins).

**Build.** No ATS changes. A standalone sender microbench modeled on the existing
`~/work/io-uring-coro-bench/scripts/sender_zc.c` (the send-op decomposition rig):
register a buffer region, stage 4×256K non-adjacent chunks, and send them via each
candidate op to a sink on **hawaii** (the M1 client; a trivial recv-and-discard).

**Measure + success criteria.** For each candidate op that the kernel accepts vs
today's 4× separate `send_zc_fixed`, over the NIC: sends/req, F_NOTIF
completions/req, `io_uring_enter`/req, cpu (cgroup usage), and `zc_copied` (must
stay 0 = true ZC). **Decision the item resolves:** does any gather+fixed combo
(a) work on this kernel and (b) beat per-block `send_zc_fixed` at 256K blocks?
- YES → the send-structure problem is solved in the op; skip WI-3, and open a
  follow-on to wire the accepted op into ATS `_write` (replace the per-run
  `send_zc_fixed` at `IOUringNetVConnection.cc:1471` with a gathered form).
- NO (kernel rejects the combos, or they don't win) → proceed with WI-3.

**Entry points.** Registered-run builder + `send_zc_fixed`:
`src/iocore/net/IOUringNetVConnection.cc:1304–1471` (`fixed_ok`/`reg_idx` at
1306–1412, the prep at 1471). Arena single-region / `buf_index 0`:
`src/iocore/io_uring/UringFixedBufArena.cc`. liburing send prototypes:
`~/work/liburing/src/include/liburing.h` (`io_uring_prep_send_zc_fixed`,
`_sendmsg_zc`).

**Effort:** ~1 day. **Gotchas:** localhost is always loopback — the sink must be
on hawaii to exercise the NIC TX path; a gathered-fixed send that silently
copy-falls-back will show `zc_copied>0` — check it per candidate.

---

## WI-2 — Watermark knee sweep (benchmark; de-risk the wm=1M recommendation)

**Goal.** Locate the smallest watermark that captures the arena win, and put the
wm=1M number on campaign-strength footing (today it is n=2).

**Why.** The root-cause session measured only wm=256K (parity) and wm=1M (−11.9%,
2 rounds). The mechanism predicts the win grows as sends/req → 1, i.e. as the
watermark approaches the object size — the knee is likely well below 1M for a
1 MiB object, which would let us recommend a smaller (cheaper-memory) watermark.

**Build.** None — records-only A/B, same as the ladder. Extend the ladder rig
(`~/work/io-uring-coro-bench`, `measure-tls-nic.sh` / the ladder driver) with a
watermark axis.

**Measure + success criteria.** 1 MiB disk-served TLS, BoringSSL, NIC, **6 rounds
interleaved same-session**, arena ON (`write_zerocopy=1`, threshold 262144, fixed
arena on), sweeping `ssl.write_buffer_water_mark` ∈ {256K, 384K, 512K, 768K, 1M};
anonymous-ZC (arena off) as the fixed comparator at each point. Per cell: cpu/1k
median (min–max), sends/req + F_NOTIF/req + copy-tail bytes/req (bpftrace, the
root-cause rig's `sendtrace.bt`), p50/p99, sys split. **Deliverable:** the
watermark→cpu/1k knee curve + the recommended production watermark, appended to
`PERF-RESULTS-2026-07-04-tls.md`. Confirms or corrects the wm=1M −11.9% at n=6.

**Effort:** ~half a day box time. **Gotchas:** the arena's top size class must be
≥ the watermark or blocks fall back to heap (silently anonymous) — verify arena
alloc counters per cell; watch the ~5% arena-only **session** swing (see Related
follow-ups) — interleave all cells in one session so the swing is common-mode.

---

## WI-3 — `vio.nbytes`-driven ciphertext block sizing  (conditional on WI-1 = NO)

**Goal.** Size `_write_buf`'s blocks per response from the known response size, so
a large response stages as one (or few) big blocks → one big `send_zc_fixed`, no
sub-threshold copy tail — without a large *static* watermark.

**Why.** The signal is in-band: the consumer's `do_io_write` sets the user write
VIO's `nbytes` when the length is known (cache hits, non-chunked pass-through —
exactly the large-object cases). Sizing to `clamp(remaining, 64K, cap)` gets
sends/req → ~1 for those, while unknown-length/chunked falls back to the adaptive
depth policy (WI-4). This is the granularity half of the unifying formula.

**Note the layer (easy to get wrong).** Under TLS the send buffer is the
**ciphertext** staging buffer, NOT the disk read buffer — encryption is a
transform between them. Sizing disk reads does nothing for TLS send structure;
size `_write_buf`. (For plain HTTP the two are the same buffer, which is why
plain-HTTP arena already wins.)

**Build.** B1 today sizes `_write_buf`'s block index once, at VC creation, from
the *static* watermark (`SSLNetVConnection.cc:917` water_mark; the arena-backing
size-index gate in `startEvent`). Change: consult the user write VIO's `nbytes`
at block-allocation time so sizing is **per response** (keep-alive connections
stream many responses through one `_write_buf` — must re-size per response, not
snapshot per connection) and bounded by WI-4's depth target. Round up to the
arena's next size class. Off (feature disabled / unknown length) → today's behavior.

**Measure + success criteria.** Large TLS at a *small* static watermark with
nbytes-sizing ON vs a large static watermark: does nbytes-sizing reach the wm=1M
cpu/1k **without** the wm=1M per-connection memory? Metrics: cpu/1k, sends/req,
copy-tail bytes/req (target ~0), peak `_write_buf` residency. Also verify small
objects and chunked responses are unchanged. TDD an engagement autest
(large known-length TLS fetch → 1 arena block, `write_zerocopy_fixed` engaged,
0 copied on loopback-counts).

**Entry points.** `_write_buf` ctor/water_mark `SSLNetVConnection.cc:902,917`;
arena-backing size-index gate in `startEvent` (the B1 change, `da9b6dc9f5`); the
`_block_alloc` hook path `src/iocore/eventsystem/IOBuffer.cc` + arena hook
`UringFixedBufArena.cc`; user write VIO nbytes on the SSL VC.

**Effort:** ~2–3 days incl. tests. **Gotchas:** per-response re-sizing on keep-alive
is the subtle part; do not regress the demand-driven backpressure the refactor
relies on (staging past the response end or past the depth target reintroduces the
bloat B1's watermark bound prevents).

---

## WI-4 — Rate-adaptive staging depth (`rate × τ`)  ❌ TRIED & REMOVED (2026-07-06)

> **Outcome: abandoned.** Implemented, then investigated on 10 GbE and removed. The
> `rate × τ` policy is sound in principle but the only available drain-rate signal
> (F_NOTIF timing under serialized ZC sends) under-reads the client rate 4–7× and never
> leaves the 256 KiB cold-start for normal speeds; and the premise fails anyway — deep
> staging is flat-benefit at 1 MiB and *counterproductive* at 8 MiB (AES-bound + cache
> pressure). The TLS write path now uses a **fixed watermark** (default 256 KiB). Full
> analysis: [`WI-4-ADAPTIVE-STAGING-REMOVED-2026-07-06.md`](WI-4-ADAPTIVE-STAGING-REMOVED-2026-07-06.md).
> The design notes below are retained for context only.

**Goal.** Bound how far encryption runs ahead of the socket to the client's actual
drain rate, so a slow client gets shallow staging (bounded memory, tight
backpressure, minimal abort-waste) and a fast client gets deep staging (big
blocks, few sends). This is the depth half of the unifying formula and the answer
to "adapt to client speed."

**Why / how it grows with client speed.** The drain rate is **free on the ZC
path**: each `F_NOTIF` completion means the kernel released those pinned bytes =
the peer ACKed, so the completion stream *is* a drain-rate clock. EWMA it →
`r`. Staging target `S = r × τ`. Client reads 2× faster → `r` doubles → `S`
doubles → blocks 2× bigger → half the sends. Grows **linearly and directly in the
measured rate** — no probing.

**Why not AIMD (evaluated, rejected).** AIMD is for *unobservable* capacity
(gropes: additive-increase-until-stall, multiplicative-decrease). Here `r` is
directly observable, so AIMD solves a harder problem than we have and adds
oscillation + a stall signal + block-size hysteresis. A fixed-N credit scheme was
also considered and is **underspecified** for this: it bounds in-flight block
*count*, not memory-*time* (N big blocks held long for a slow client = lots of
pinned bytes). Credits are a fine *enforcement mechanism* (release-triggered
refill) but the *target* must be `r × τ`, not a fixed count.

**Build.** (a) Maintain an EWMA drain-rate estimate per SSL VC from `_write`'s
F_NOTIF completions (bytes released, timestamp). (b) Gate `SSL_write` encrypt-ahead
on `staged_bytes < S = r × τ` instead of (or in addition to) the static high-water.
(c) Feed `S` into the block-size clamp (composes with WI-3's `remaining`). Cold
start (first response, no estimate) → a middle default (e.g. 256K), adapt.

**Measure + success criteria.** Sweep client bandwidth (wrk connections / tc-netem
rate shaping on hawaii, or slow-reader clients): for each client speed, compare
adaptive vs {static 256K, static 1M} on cpu/1k AND peak `_write_buf` residency
(memory). **Success = adaptive matches-or-beats the better static setting at every
client speed** (the headline hypothesis) — cpu near static-1M for fast clients,
memory near static-256K for slow clients. Also confirm backpressure: upstream
(cache/origin) feels a slow client within ~2 blocks, not 1 MiB.

**Entry points.** F_NOTIF completion handling in `_write`
`IOUringNetVConnection.cc:1445–1490` (the ZC drain loop + `zc_stat`/notif); the
encrypt-ahead high-water break `SSLNetVConnection.cc:838–840`
(`_write_buf->high_water()`); watermark source `:917`.

**Effort:** ~3–4 days incl. the bandwidth-sweep harness. **Gotchas:** τ choice
trades latency vs granularity — sweep it; a slow client with `S` small reintroduces
the send split (correct tradeoff — slow clients aren't CPU-bound), so don't "fix"
it back to big blocks; TCP_INFO delivery_rate is an alternative rate source if the
F_NOTIF cadence proves too coarse.

---

## Recommended order & dependency graph

```
WI-1 (kernel spike, gate) ──► if YES: send-structure solved in the op
   │                                  → follow-on: wire gathered-fixed into _write
   │                                  → SKIP WI-3;   ship WI-1 + WI-4
   └► if NO:  ─────────────────────► WI-3 (granularity via block sizing)
WI-2 (knee sweep) — independent, cheap, run anytime (de-risks current wm=1M advice)
WI-4 (depth policy) — needed in ALL outcomes; the "adapt to client speed" half
```
Ship target either way: **granularity** (WI-1 op *or* WI-3 sizing) + **depth**
(WI-4), converging on the unifying `clamp(min(rate×τ, remaining), 64K, top_class)`.

---

## Shared method appendix (the established rig — read before benchmarking)

- **Rig:** `~/work/io-uring-coro-bench` (own git repo). `scripts/setup-box.sh up`
  before, `down` after (restore even on failure). cgroup-v2 cpuset is the only
  pinning that sticks: ATS on P-cores 0,2,4,6; NIC IRQs on E-cores; client on
  hawaii. Box otherwise quiet.
- **NIC:** atlantic 1 GbE `enp6s0` → **hawaii** (M1 Mac, passwordless ssh,
  `/opt/homebrew/bin/wrk`, workdir `/Users/mo/work`). localhost is always loopback
  — a real second host is required to exercise NIC TX. IOMMU group 18 = `identity`
  (verify). 1 GbE is wire-limiting — probe ceilings, run at ~70%, NO throughput claims.
- **Gold metric:** cgroup `cpu.stat usage_usec` ÷ requests (`cpu/1k`); also req/s,
  p50/p99, user/system split. Medians with (min–max). ONE binary per campaign,
  cells differ only by records. Interleave cells same-session (cross-session drift
  is ±~2%; the arena cell alone swings ~5% — keep it common-mode).
- **TLS binary:** BoringSSL Release `build-bssl-rel` → `/tmp/ts-bssl-rel` (shared
  libs mandatory — static .a break ATS feature probes). Verify `ldd` shows BoringSSL.
- **Build discipline:** foreground only, `cmake --build <dir> -j$(nproc)` with a
  long timeout, re-invoke on timeout (ninja incremental) until exit 0; never
  background a build. `cmake --install` before any autest. Autests need
  `--build-root <matching builddir>` or 11 TLS plugin tests silently fail.
- **Instrumentation:** hybrid PMU `cpu_core/<ev>/`; non-PEBS DWARF for flamegraphs
  (`-e cpu-clock -F999 -g --call-graph dwarf,32768`); `sudo perf -f` for mo-owned
  data. Send-op tracing: the root-cause session's `sendtrace.bt` (bpftrace,
  sends/notifs/req) + `perfstat-round.sh`. Big captures → `/tmp/iou-perf`.
- **Records knobs:** `net.io_uring.enabled`, `net.io_uring.write_zerocopy`,
  `net.io_uring.write_zerocopy_threshold` (default 262144),
  `ssl.write_buffer_water_mark`, the fixed-arena enable/size-class config.
  Engagement metrics: `proxy.process.net.io_uring.write_zerocopy{,_fixed,_copied}`
  and the arena `fixed_arena.*.{alloc,free,in_use,class_exhausted,oversize_fallback}`.

## Related already-tracked follow-ups (not expanded here; in the ledger/memory)

- The ~5% **arena-only session swing** — unexplained; THP/IRQ/IOMMU ruled out,
  hawaii TCP/ACK + NIC coalescing drift untested. Confounds WI-2/WI-4 — interleave.
- Gate the unconditional `do_poll(0)` on the poll-bridge CQE
  (`NetHandler.cc:483`, ~4% loopback).
- Async `TS_EVENT_ERROR` reenable regression test (needs new plugin infra).
- The large-object **loopback** bimodality (parked; did not reappear on NIC).
