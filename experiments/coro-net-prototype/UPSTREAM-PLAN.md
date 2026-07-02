# io_uring coroutine net-path: upstream decomposition plan

How to land the `io-uring-coroutine-wip` work on `apache/trafficserver` master as an
ordered sequence of independently-reviewable PRs. Written 2026-07-01.

## Scope

Branch is 68 non-merge commits ahead of `origin/master`. Against the merge-base
(`b13b9858ac`) the branch changes **87 files, ~14.7k insertions**. Excluding the
out-of-tree research spike and local tooling (see "Exclude" below), the shippable
production surface is roughly:

- `include/iocore/io_uring/Coroutine.h` (564) + `UringFixedBufArena.h` (204) + `IO_URING.h` (+16)
- `src/iocore/net/IOUringNetVConnection.cc` (1617) + `P_IOUringNetVConnection.h` (190) + `P_IOUringNetAccept.h` (57)
- net wiring: `NetHandler.cc` (+145), `UnixNetAccept.cc` (+149), `UnixNetProcessor.cc` (+46), `UnixNet.cc` (+7), `net/CMakeLists.txt`
- `src/iocore/io_uring/UringFixedBufArena.cc` (296) + `io_uring.cc` (+70) + `io_uring/CMakeLists.txt`
- eventsystem/cache hooks: `IOBuffer.h` (+21), `P_IOBuffer.h` (+16), `CacheVC.cc` (+19), `ink_queue.{h,cc}` (+12)
- config: `RecordsConfig.cc` (+20), `HttpConfig.cc` (+14), `HttpSM.cc` (+40)
- unit tests: `test_coroutine.cc` (526), `test_fixed_arena.cc` (259), `test_IOBuffer.cc` (+63)
- ~25 autests under `tests/gold_tests/io_uring/`
- docs: `doc/developer-guide/.../netvconnection-invariants.en.rst` (371)
- one unrelated robustness fix: `traffic_crashlog.cc` (+11)

## Build-flag / optional-dependency story (applies to every PR below)

No new dependency and no change to default builds. The gating already exists upstream
for the io_uring **disk-AIO** backend and is reused verbatim:

- `CMakeLists.txt:388` auto-detects liburing: `check_symbol_exists(io_uring_queue_init "liburing.h" HAVE_IOURING)`.
- `CMakeLists.txt:430` `option(USE_IOURING "Use experimental io_uring (linux only)" 0)` — **default OFF**.
- Only when `HAVE_IOURING AND USE_IOURING` is `TS_USE_LINUX_IO_URING=1` set.
- Every new net-path/arena source is wrapped in `#if TS_USE_LINUX_IO_URING` (e.g.
  `IOUringNetVConnection.cc:26`). A stock build (no liburing, or `-DUSE_IOURING=0`)
  compiles the translation units to empty and links unchanged.
- Second gate at **runtime**: `proxy.config.net.io_uring.enabled` defaults `0`, so even a
  liburing-enabled build keeps the epoll `UnixNetVConnection` unless explicitly opted in.
- `CMAKE_CXX_STANDARD` is already `20`, so the coroutine runtime needs no toolchain bump;
  the coroutine header only compiles under `TS_USE_LINUX_IO_URING`.

Net: this is opt-in at build time (liburing + `-DUSE_IOURING=1`) *and* opt-in at runtime.
Lead every PR description with this so reviewers know default builds carry zero risk.

## Ordered PR sequence

### PR 1 (independent) — traffic_crashlog: well-formed report on empty backtrace
- Commit: `1b4f12f7ec`. File: `src/traffic_crashlog/traffic_crashlog.cc` (+11).
- Not io_uring-specific; surfaced as a secondary SIGSEGV in `traffic_crashlog.cc` when the
  primary process dies before a backtrace is available. Ship it on its own — it stands
  alone, needs no io_uring build, and de-risks the rest.
- Dependencies: none.
- Reviewer concerns: (1) confirm the empty-backtrace path is real and not masking the
  primary crash; (2) keep the diff minimal (no drive-by crashlog refactor).

### PR 2 (independent, optional) — developer-guide: NetVConnection invariants
- Commit: `1f2bdeb134`. Files: `doc/developer-guide/.../netvconnection-invariants.en.rst`
  (371) + `index.en.rst` (+1).
- Documents the existing NetVC/VIO producer-consumer contract (drain-per-READ_READY, no
  resignal for buffered data, demand-driven write, etc.). Independent of io_uring and
  valuable on its own; it is also the spec the io_uring VC must honor, so landing it first
  gives reviewers of PR 4 a shared vocabulary.
- Dependencies: none. Can land in parallel with PR 1.
- Reviewer concerns: (1) it must describe *master* behavior, not io_uring behavior; (2)
  doc-build (Sphinx) passes.

### PR 3 — io_uring coroutine runtime
- Commits: `57a49fee73` (Coroutine.h), `ba6c121c4d` + `f537b41681` (unit test +
  Catch2WithMain link), `73ed24f9a2` (rename `UringOp/UringCancel::_res` to dodge the
  `<resolv.h>` `_res` macro), `68486a0990` (per-thread coroutine frame pool: Coroutine.h +
  `ink_queue.{h,cc}` helper).
- Files: `include/iocore/io_uring/Coroutine.h`, `src/iocore/io_uring/unit_tests/test_coroutine.cc`,
  `include/iocore/io_uring/IO_URING.h`, `include/tscore/ink_queue.h`, `src/tscore/ink_queue.cc`,
  `src/iocore/io_uring/CMakeLists.txt`.
- A header-only C++20 coroutine layer over the existing per-thread `IOUringContext`
  (awaitables that suspend on an SQE and resume on the CQE), plus a per-thread `FramePool`
  that recycles coroutine frames via an `InkFreeList`-style stack. Standalone: builds and
  its Catch2 test (`test_iouring_coro`) runs with only the io_uring subsystem, no net path.
- Dependencies: none beyond the existing io_uring subsystem. First in the io_uring chain.
- Reviewer concerns: (1) **frame-pool correctness/lifetime** — a custom coroutine
  `operator new`/`delete` backed by a thread-local pool; reviewers will want proof it can't
  hand a frame to the wrong thread or outlive the EThread, and justification vs. plain heap
  frames (the answer is the epoll-parity perf result). (2) **API surface & placement** — is
  a general coroutine runtime warranted in `include/iocore/io_uring`, and is the awaitable
  set the minimal one; also flag the `_res` macro-collision rename as a portability wart.

### PR 4 — io_uring NetVConnection + socket lifecycle (single-shot recvmsg/sendmsg)
- Commit groups (squash the intra-branch churn — e.g. `2e4b4b4318` "free_thread choke
  point" and its revert `501430bfce` cancel out and should not appear upstream):
  - VC + selection: `1ad643a8ca` (add `IOUringNetVConnection` subclass), `863b37f58f`
    (select via `net.io_uring.enabled`), `a705a31aef` (plain-HTTP autest).
  - read/write via io_uring: `c9db816bfa` (recvmsg read), `c98b224825` (sendmsg write),
    `2b99c9289d` (load/large-body test), `28c6784f9f` (fully completion-driven, no epoll),
    `450db40b59` (epoll parity + cross-thread doorbell + async batched write).
  - connect/accept: `eef3f4ad73` + `f62cb7eb56` (io_uring-native connect + test),
    `982b9a3878` (io_uring accept, `P_IOUringNetAccept.h`).
  - lifecycle/teardown: `2620012eff` (deferred-close counter), `e86acb5fb5` (defer VC free
    while an op is in flight), `e3dfa6d7fe` (retry a deferred-close cancel the SQ rejected).
  - DNS bridge: `4253f384c0` (`IOUringPollBridge` — multishot-poll the thread's epoll fd
    into the ring so DNS UDP sockets are serviced while the thread blocks in the ring) +
    `e11d06b145` (DNS autest).
  - correctness fixes for the single-shot read/write buffer races: `bfb14a84ea` (pin recv
    destination blocks across the await), `05492305a1` (don't consume a write source buffer
    freed mid-send), `06719ea339` (drop a recv whose producer was destroyed), `c5eddb3485`
    (hold a recv that completes while the read is disabled), `e4fb153a31` (redirect an
    in-flight recv when its buffer is re-targeted).
  - pool guard: `7712cb6212` (Fatal at startup if `io_uring.enabled=1` with a non-`thread`
    `server_session_sharing.pool`; `HttpConfig.cc`).
  - TSan: `bbafdc6d9c` (`.tsan_suppressions` for the benign freelist-accounting race).
- Files: `IOUringNetVConnection.cc`, `P_IOUringNetVConnection.h`, `P_IOUringNetAccept.h`,
  `NetHandler.cc`, `UnixNetAccept.cc`, `UnixNetProcessor.cc`, `UnixNet.cc`, `HttpConfig.cc`,
  `RecordsConfig.cc` (only `io_uring.enabled` for this PR), `net/CMakeLists.txt`,
  `.tsan_suppressions`, and the non-provided-buffer autests (`io_uring_netvc`, `_read`,
  `_connect`, `_connect_timeout`, `_origin_timeout`, `_timeout_variants`, `_close_inflight`,
  `_read_eos_reset`, `_read_backpressure`, `_dns`, `_pipelining`, `_post_abort`, `_chunked`,
  `_empty_body`, `_drip_origin`, `_keepalive_rearm`).
- A correct, self-contained io_uring net path: single-shot `recvmsg`/`sendmsg`, io_uring
  connect/accept, completion-driven teardown, epoll-free operation with the DNS poll bridge.
  Works and is ASan/TSan-clean with `read_provided_buffers` absent (single-shot only).
- Dependencies: PR 3 (uses the coroutine runtime).
- Reviewer concerns: (1) **thread-confinement / teardown state machine** — in-flight ops
  live on the owning EThread's ring and can only be cancelled there; the deferred-free +
  cancel-then-unwind path and the global-pool startup rejection encode that invariant. The
  churn here (a commit and its revert) means reviewers will demand the teardown be provably
  leak/double-free-free. (2) **architecture** — is subclassing `UnixNetVConnection` and
  bolting on `IOUringPollBridge` the right shape, or does it argue for a transport
  abstraction; and is the epoll-fd bridge audit complete (which registered fds still need
  it). Expect a request to justify the whole subclass vs. epoll for a Linux-only path.

### PR 5 — provided-buffer read path (the default)
- Commits: `3d8900f737` (provided-buffer ring + awaitable — strip the pure-multishot recv
  bits, see Exclude), `4354b93acf` (single-shot provided-buffer read path), `5bb7b67edf`
  (make provided-buffers the default; harden disabled-handling; `-ENOBUFS` falls back to
  single-shot `_read`).
- Files: `IOUringNetVConnection.cc`, `P_IOUringNetVConnection.h`, `IO_URING.h`,
  `RecordsConfig.cc` (`read_provided_buffers` default 1, `read_buffer_count` 1024,
  `read_buffer_size` 32768), autests `io_uring_read_provided`, `io_uring_read_singleshot`
  (+origin), `io_uring_provided_enobufs`.
- The kernel late-binds a ring buffer to each recv and the completion zero-copy-attaches it
  to the consumer's *current* buffer, decoupling the recv destination from the consumer
  buffer. This dissolves the whole single-shot buffer-churn race class (the PR-4 fixes
  become the fallback path). Flips the read default; single-shot `_read` stays as fallback.
- Dependencies: PR 4.
- Reviewer concerns: (1) **pinned-memory accounting + fallback** —
  `read_buffer_count × read_buffer_size` is per-thread pinned memory (defaults 1024×32K =
  32 MiB/thread); and the `-ENOBUFS` fallback to single-shot exists to avoid a deadlock when
  one connection must buffer more than the whole ring — both need clear docs and correctness
  argument. (2) **disabled-read semantics** — recv is destructive, so a buffer that fills
  while the read is disabled must be held and replayed, and EOS/error suppressed until
  re-arm; this is the subtlest correctness surface and will draw the most scrutiny.

### PR 6 (experimental, OFF by default) — registered arena + send_zc_fixed
- Commits: `f04421015b` (MIOBuffer block-alloc hook + arena recv hook), `461f395ef2`
  (registered-buffer arena drawn from the cache Doc buffer), `865f8ef910` (`send_zc`/
  `send_zc_fixed` write path, flag-gated), `0bc94c7528` (`write_zerocopy_threshold` default
  256K), `8355f49c91` (size-class partition of the arena), `354a659317` (lock-free
  `InkAtomicList` arena pool), `0c12dded59` (zero-copy + arena gold test).
- Files: `UringFixedBufArena.{h,cc}`, `io_uring.cc` (`register_fixed_buffers`), `IO_URING.h`,
  `CacheVC.cc`, `IOBuffer.h`, `P_IOBuffer.h`, `test_fixed_arena.cc`, `test_IOBuffer.cc`,
  `RecordsConfig.cc` (`write_zerocopy`, `write_zerocopy_threshold`, `fixed_arena_size` (0=off),
  `fixed_arena_block_size`), autests `io_uring_write_zerocopy*`.
- All defaults off (`write_zerocopy=0`, `fixed_arena_size=0`). Landing it as an explicitly
  experimental, off-by-default layer keeps the win available for operators to A/B while
  isolating its cross-subsystem reach from the core net path.
- Dependencies: PR 4 (PR 5 not strictly required, but sequence it last).
- Reviewer concerns: (1) **registered-buffer lifetime vs. `send_zc` F_NOTIF** — an arena
  block must not be recycled until its zero-copy notification lands (refcount-gated recycle
  via the `_write` Ptr anchor); reviewers will hunt for DMA-after-free on the recycle path,
  and will note per-ring registration multiplies `RLIMIT_MEMLOCK` (no `CLONE_BUFFERS` yet).
  (2) **cross-subsystem coupling for an off-by-default feature** — the MIOBuffer block-alloc
  hook and `CacheVC` drawing Doc buffers from the arena couple eventsystem + cache to
  io_uring; expect pushback on that coupling plus a demand for the perf justification (the
  win is real only for large disk-served objects on a real NIC under `iommu=pt`; it loses on
  small objects — see PERF-RESULTS).

## Explicitly EXCLUDE from initial upstreaming

- **The research spike + perf study**: the entire `experiments/coro-net-prototype/` tree
  (standalone prototype `coro_netvc/async_socket/epoll_backend/uring_backend/reactor`, its
  `CMakeLists.txt`, `run-matrix.sh`, and all `DECISIONS.md`/`PERF-*.md`/`README`/`NEXT-STEPS`
  narrative) and every `coro-net:` doc commit. Keep as branch/internal history; optionally
  distill one architecture note into `doc/` later. Not production code.
- **Local tooling**: `.claude/` hooks + `settings.json`, session-start hook commits.
- **read_fixed (T3.6)**: not implemented on this branch, and by design excluded — the cache
  opens `O_DIRECT` so the disk read already DMAs with no copy; `read_fixed` buys ~0.07% while
  threading a `registered_index` through the AIO subsystem (`AIOCallback`). An upstream
  reviewer would rightly question AIO-subsystem complexity for that gain.
- **Experimental multishot recv** (`ceea0eaff0`, and the multishot bits of `3d8900f737`):
  tried and superseded by single-shot + provided buffers; its `io_uring_read_multishot`
  autest is already gone from the tree. Ship only the provided-buffer ring infrastructure.
- **recv_coalesce** (`552a8ec1a1`, `bbc4dc7505`; `recv_coalesce*` records, `HttpSM.cc` +40,
  `NetVConnection.h` +9 public API): marked NO-GO for general prod (needs a high `lowat`
  unsafe for TLS/H2, moot for H2 by the framing copy). Excluding it also keeps the public
  `NetVConnection.h` API untouched. Defer.
- **IORING_REGISTER_CLONE_BUFFERS (T3.2)**: not implemented; would reduce per-ring memlock —
  a follow-up to PR 6.
- **TLS / HTTP-2 over io_uring**: blocked on the SSLNetVConnection layering refactor. Today
  `net.io_uring.enabled` only selects the plain VC in `UnixNetProcessor`; forcing it on
  breaks TLS accept. Out of scope until the TLS refactor lands, after which io_uring is an
  orthogonal transport underneath TLS.

## Tests & mechanics

- The ~25 `tests/gold_tests/io_uring/` autests each self-enable io_uring and assert
  "io_uring NetVConnection enabled"; split them across PRs 4/5/6 by which path they exercise
  (list above). Run them in one invocation or with distinct `AUTEST_PORT_OFFSET` — concurrent
  invocations collide on ports.
- Fold the working-tree test edits (currently uncommitted: `traffic_crashlog.cc` + four
  `io_uring_*` test files) into their owning PRs before submitting.
- Squash intra-branch back-and-forth (notably `2e4b4b4318` + revert `501430bfce`) so upstream
  history shows only net changes.
