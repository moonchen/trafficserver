# WI-4 Rate-Adaptive TLS Write Staging — Investigation & Removal (2026-07-06)

## Verdict

WI-4 (`proxy.config.net.io_uring.write_adaptive_depth`) was investigated end-to-end
on real 10 GbE hardware and found to be **non-functional in practice** and built on a
**premise the data does not support**. It has been **removed**. The TLS write path
reverts to a **fixed `ssl.write_buffer_water_mark`**, whose default is raised from
64 KiB to **256 KiB** (rationale in §5).

This **supersedes** the "WI-4 — validated" section of
`PERF-RESULTS-2026-07-04-tls.md`: those numbers do not mean what they claimed
(reconciliation in §6).

---

## 1. What WI-4 was, and what started this

WI-4 self-tuned the ciphertext staging depth `S = drain_rate × τ` from an EWMA of the
client's drain rate, aiming to give fast clients a deep encrypt-ahead buffer and slow
clients a shallow one. The investigation began from a genuine bug in that path
(`high_water` masking the adaptive target); chasing it correctly revealed that the
whole mechanism does not work.

Findings below are ordered by significance — the estimator defect (§2) is the
load-bearing one; the `high_water` bug (§4) that started it is comparatively minor.

---

## 2. The rate estimator does not work across normal client speeds — **load-bearing finding**

The drain-rate estimate is fed **only** by zero-copy `F_NOTIF` completions
(`IOUringNetVConnection.cc`), and zero-copy only engages when a send is `≥ 256 KiB`
(the ZC threshold). A client slow enough to warrant `S < 256 KiB` therefore produces
**no** rate sample and stays pinned at the 256 KiB cold-start — a self-reinforcing
floor at the ZC threshold. Even when ZC does fire, per-VC send **serialization**
(one send in flight, awaiting the notification before the next) makes the measured
rate the serialized-loop throughput, not the link rate.

Measured (256 MiB object, τ=50 ms, `results/tls-curve.csv`), converged `S` = median
`stage_target`:

| client rate | `S = r·τ` should be | **`S` measured** |
|---|---|---|
| 500 kbit | 64 KiB (floor) | **256 KiB** |
| 2 Mbit | 64 KiB | **256 KiB** |
| 16 Mbit | 98 KiB | **256 KiB** |
| 64 Mbit | 391 KiB | **256 KiB** |
| 256 Mbit | ~1 MiB | **256 KiB** |
| **1 Gbit** | ~1 MiB | **256 KiB** |
| 2 Gbit | — | 1.7 MiB |
| unshaped (~5 Gbit) | — | 21 MiB |

`S` is pinned at the 256 KiB cold-start across the **entire realistic range
(500 kbit → 1 Gbit)**; it only adapts *up* above ~2 Gbit. In practice adaptive is a
**de-facto fixed 256 KiB watermark** that lands near a reasonable value *by accident*.

Direct instrumentation of `_adaptive_rate_bps` confirmed the estimate **under-reads
the client rate 4–7×** (lowering the ZC threshold to 4 KiB did **not** fix it):

| actual rate | estimator converged to | ratio |
|---|---|---|
| 2 Mbit | 542 kbit | 0.27× |
| 32 Mbit | 6.3 Mbit | 0.20× |
| 512 Mbit | 78 Mbit | 0.15× |

---

## 3. Deep staging has no benefit regime — the premise is unsupported

Static-watermark cpu/1k sweeps on real NIC (arena+ZC cell, BoringSSL):

**1 MiB object** (`results/tlsnic-wm-large-verify.csv`, 4 passes) — flat:

| watermark | cpu/1k |
|---|---|
| 256 KiB | 1.172 |
| 384 KiB | 1.158 |
| 512 KiB | 1.162 |
| 1 MiB | 1.162 |

**8 MiB object** (`results/tlsnic-wm-huge8.csv`, 4 passes) — cpu/1k **rises** with depth:

| watermark | cpu/1k | vs 256 KiB |
|---|---|---|
| 256 KiB | 9.53 | — (best) |
| 512 KiB | 9.78 | +2.7% |
| 1 MiB | 10.29 | +8.0% |
| 4 MiB | 10.65 | +11.7% |

The knee does **not** move up for large objects — it moves **down**. TLS cpu is
AES-bound (~8 ms / 8 MiB → cpu/1k ~10), and a multi-MB per-connection staging buffer
(× many conns) thrashes L2/L3, adding stall cycles the syscall savings don't offset.
This is consistent with the earlier "TLS ~2× footprint amplifies cold-line residual"
finding. **The one scenario that could have justified deep adaptive staging —
large objects — instead shows deep staging is counterproductive.**

The real ZC benefit is **arena-vs-anonymous** (−13.4% here), present at *every*
watermark; it is not a staging-depth effect.

---

## 4. The `high_water` bug that started this — real but narrow

The encrypt-ahead loop checks its `high_water()` gate **after** staging a whole
plaintext block, and `ssl.max_record_size` defaults to 0 (uncapped), so one iteration
stages a whole block. The static 64 KiB mark therefore does **not** cap at 64 KiB — it
caps at "one plaintext block past the mark" (measured 131 KiB unthrottled → 325 KiB
when the block coalesces). The bug only bites when plaintext blocks are *smaller* than
the target AND several are queued (e.g. `ssl.max_record_size` set). Removed along with
the rest of the adaptive path; a fixed watermark sidesteps it entirely.

---

## 5. Adaptive only adds cost; robustness is fine

- **Unbounded `S`** for fast clients: 21 MB staged in a single pass at unshaped
  (~5 Gbit) — real memory exposure, no cap.
- **Cold-start over-staging under slowloris**: 1000 readers @ 16 kbit each — adaptive
  holds **349 KiB/conn (340 MB)** because every slow conn is pinned at the 256 KiB
  cold-start, vs a static 1 MiB watermark's **174 KiB/conn (170 MB)** (which
  backpressures down for ultra-slow readers). The hoped-for "adaptive protects memory
  under many slow clients" is **inverted**.
- **No breakage** at any rate (250 kbit → unshaped) or under 1000-conn slowloris — no
  crash/assert; memory bounded. The one clean positive, and it holds for the fixed
  watermark too.

---

## 6. Reconciliation of the committed "WI-4 validated" numbers

`PERF-RESULTS-2026-07-04-tls.md` reported WI-4 "validated (self-tuning cpu win)". That
is **not** what was measured:

- The results CSV (`results/tlsnic-adaptive.csv`, dated Jul 5 23:52) predates the
  config-check commit (`7979f091a8`, Jul 6 11:38), and the harness's `adaptive` cell
  set a **manual** `SSLWM=2 MiB`. So the numbers came from a pre-check binary running
  the **manual-watermark workaround** — i.e. a fixed 2 MiB watermark, not adaptation.
- `peak_inuse` for that cell (31–38 MB) tracks static1m, confirming it staged deep via
  the manual watermark, not any drain-rate tuning.
- On the committed binary the committed config **could not boot** (the check `DL_Fatal`s
  `adaptive + non-default watermark`).

So the "adaptive matches-or-beats static1m" result is consistent with adaptive simply
**being** a fixed watermark. Nothing to preserve; the fixed-watermark path is the
honest version of the same behavior.

---

## Decision & change

**Removed** the adaptive machinery; **fixed watermark** retained, **default raised
64 KiB → 256 KiB**.

Why 256 KiB: optimal for 8 MiB objects, within 1% of optimal for 1 MiB, equal to the
ZC engagement threshold (so staged ciphertext is exactly ZC-eligible), and a modest 4×
over the prior default. 384 KiB is an equally defensible "plateau top" if a hair more
depth is wanted for 1 MiB objects; deeper than that only costs memory (and cpu for
large objects). This is a **global** `ssl.write_buffer_water_mark` default change —
operators who want the old conservative memory profile can set it back to 65536.

**Removed** (commit-level revert of `7979f091a8` plus the uncommitted fix work):

| file | what |
|---|---|
| `IOUringNetVConnection.cc` / `.h` | `adaptive_stage_target()`, `_adaptive_note_drain()`, the rate EWMA state, `write_adaptive_depth`/`tau_ms` globals |
| `SSLNetVConnection.cc` / `P_SSLNetVConnection.h` | the encrypt-path adaptive block + gate term, the `write_adaptive_staged` counter, `_io_transport` plumbing |
| `SSLConfig.cc` | the adaptive-vs-watermark `DL_Fatal` mutual-exclusion check; default → 262144 |
| `RecordsConfig.cc` | `write_adaptive_depth`, `write_adaptive_tau_ms` records; `ssl.write_buffer_water_mark` default → 262144 |
| `UringFixedBufArena.h` | `top_block_size()` (adaptive-only) |
| `tests/gold_tests/io_uring/io_uring_tls_adaptive_stage.test.py` | the adaptive gold test (never committed) |

Verified: builds clean; `io_uring_tls` + `io_uring_tls_write_zc` autests pass; no
orphaned adaptive symbols remain.

---

## Method & data

Rig: `~/work/io-uring-coro-bench` (own git repo). 10 GbE path = hawaii en7 (.220);
harnesses force+verify en7 (curl `--interface en7` + box-side established-peer guard).

- Staging-vs-rate curve + slowloris: `scripts/measure-tls-curve.sh`,
  `results/tls-curve.csv` (256 MiB object, geometric rate sweep, no-completion window).
- Watermark knee, 1 MiB: `scripts/campaign-tls-wm.sh` →
  `results/tlsnic-wm-large-verify.csv`.
- Watermark knee, 8 MiB: `scripts/measure-tls-nic.sh` (workload `huge8`) →
  `results/tlsnic-wm-huge8.csv`.

Harness note: `measure-tls-nic.sh`'s cgroup pinning check now excludes `iou-wrk-*`
io_uring WQ workers (kernel blocking-I/O helpers that don't honor the cpuset and float
to non-isolated cores; their disk cost is ~constant across the watermark sweep).
