# io_uring write-path: Tier 2 / Tier 3 execution plan

Self-contained handoff so a fresh session can run "work on tier 2/3" without re-deriving context.
Background + evidence: this file's siblings in `experiments/coro-net-prototype/DECISIONS.md`; capstone
memory `io-uring-write-zc-and-master-demo.md`. Branch `io-uring-coroutine-wip`.

## Current committed state (as of HEAD ~b451cf1ecc)

Two proven wins, both flag-gated, validated on the real NIC (atlantic 1GbE -> host `hawaii`):
- **Batched submission** (the io_uring net path itself): -5..6% total cpu/1k vs epoll on small-object
  (4 KB) cache hits, consistent across 128-512 conns. Toggle: `proxy.config.net.io_uring.enabled`.
- **Zero-copy send for large objects**: anon `send_zc` -38%, `send_zc_fixed` (registered arena) -42%
  vs copy, on **disk-served** 1 MiB objects under iommu=pt. Toggles: `write_zerocopy` (off),
  `write_zerocopy_threshold` (262144 = 256 KB default, the cold crossover), `fixed_arena_size` (0=off),
  `fixed_arena_block_size` (1 MiB).

Code map:
- Arena: `include/iocore/io_uring/UringFixedBufArena.{h,cc}` (singleton, mmap region, mutex free-stack,
  `RegisteredBufferData : IOBufferData` recycle-on-free). `IOBufferData::registered_index()` virtual.
- Registration hook: `IOUringContext::register_fixed_buffers()` (`src/iocore/io_uring/io_uring.cc`).
- Cache source: `CacheVC::handleRead` (`src/iocore/cache/CacheVC.cc`, ~line 477) draws the Doc buffer
  from the arena for reads >= 65536.
- Send path: `IOUringNetVConnection::_write` (`src/iocore/net/IOUringNetVConnection.cc`) -- the iovec
  build stops at a registered-ness/contiguity boundary (header/body split), and emits send_zc_fixed
  for a contiguous registered run, anon send_zc otherwise, plain copy below the threshold.
- Config: `src/records/RecordsConfig.cc` (search `io_uring.write_zerocopy` / `fixed_arena`).

## Reusable recipes (REQUIRED -- non-obvious)

- **Builds**: `cmake --build build-dev --target traffic_server` (autests/ASan), `build-fp` (perf,
  frame pointers), `build-dev-asan` (ASan). ALWAYS `cmake --install <dir>` after (autests/benchmarks
  run the installed tree, not the build dir). Installs: build-dev->/tmp/ats-dev, build-fp->/tmp/ts-iou-fp,
  build-dev-asan->/tmp/ats-dev-asan.
- **iommu=pt on the NIC (no reboot)**: `echo 0000:06:00.0 | sudo tee /sys/bus/pci/drivers/atlantic/unbind`
  -> `echo identity | sudo tee /sys/kernel/iommu_groups/18/type` -> `echo 0000:06:00.0 | sudo tee
  /sys/bus/pci/drivers/atlantic/bind` -> `sudo nmcli con up enp6s0`. (GRUB already has iommu=pt for the
  next reboot; the box is currently left in `identity`.) Bare metal => pt is the realistic prod config.
- **Forcing the arena/disk-read path**: small RAM cache (`cache.ram_cache.size: 524288`) + ROUND-ROBIN
  reads over ~50 distinct 1 MiB objects (nginx `/L1m/0..49.bin`, Host `perf.test`). Hammering ONE object
  serves it from the agg/open-read buffer and NEVER disk-reads -> arena never engages. The round-robin
  closes each object's open-read with intervening reads, forcing disk reads -> arena. Confirm via
  `proxy.process.net.io_uring.write_zerocopy_fixed > 0` and `..write_zerocopy_copied == 0` (true ZC).
- **Harnesses** (`~/work/io-uring-coro-bench/scripts/`, own git repo): `setup-box.sh up/down` (cgroup
  cpuset pin + governor), `measure-fixed-ab.sh <copy|anon|fixed>` (the 3-mode large-obj A/B, has the
  round-robin + restart logic), `measure-nic2.sh <label> <bin> <0|1> hot4k <conns> <dur>` (small-obj
  io_uring-vs-epoll, same binary toggled), `sender_zc.c` (isolated send_zc microbench, COLD-cycles a
  256 MB buffer; sink = `python3 /tmp/sink.py` on hawaii). `pristine` binary copy for the on/off toggle.
- **wrk on hawaii**: `/opt/homebrew/bin/wrk`, lua at `/Users/mo/work/nic-send-test/` (`l1m_rr.lua`
  round-robins /L1m/, `obj.lua` for 4 KB). hawaii LAN ip 192.168.1.220; this box NIC 192.168.1.165.
- Gotchas: see [[ats-benchmarking-pitfalls]] (remap key no :port, validate 200+size, cache file
  `truncate`-precreated, cgroup not taskset). Shell here has set -e -> guard `pkill` etc. with `|| true`.

## TIER 2 -- harden the net path for shipping

T2.1 **Large-object zero-copy autest** (Tier-1 tail). DONE -- `tests/gold_tests/io_uring/
  io_uring_write_zerocopy.test.py` (+ `io_uring_write_zerocopy_rr.lua`). Five phases: warm (miss->disk
  write), cache-hit body integrity, wrk round-robin load (disk reads -> arena + churn), abort mid-read
  (curl | head -c 4096 closes while a send_zc + NOTIF are in flight), and a metric gate. Validated under
  ASan (build-dev-asan) AND non-ASan Debug: 5/5 phases pass, body intact, no crash, `write_zerocopy`
  and `write_zerocopy_fixed` both engage (measured zerocopy=5121 / fixed=4581 -- ~89% through the
  registered arena). Combined with T3.5 (the abort phase IS the arena-lifetime ASan workload).
  KEY FINDING: a block must hold the whole on-disk **Doc** (Doc struct + marshalled header + body), not
  just the body -- a nominal "1 MiB" object is ~1 MiB body + overhead > a 1 MiB block, so `alloc()`
  returns nullptr (`req_bytes > block_size`) and silently falls back to a heap buffer (no send_zc_fixed,
  fixed stays 0). The test uses 2 MiB blocks. So the shipped default `fixed_arena_block_size=1048576`
  is effectively too small for 1 MiB objects -- motivates T3.3 (size classes) and is a config-doc note.
  Run: `cd tests && ./autest.sh --ats-bin=/tmp/ats-dev-asan/bin --sandbox=/tmp/sb --filter=io_uring_write_zerocopy`
  (filter flag is `-f/--filters`, glob-capable; the old note's `-R` is actually `--reporters`). autest
  exec's a command with no shell operator directly (no `sh -c`), so bash `$` must be escaped `$$` and an
  env-var prefix like `VAR=x cmd` fails -- pass config another way.

T2.2 **Full autest suite + ASan** with `io_uring.enabled=1` (and a cell with `write_zerocopy=1`).
  io_uring_* suite: all 6 gold tests (which set `enabled=1` themselves, + a `write_zerocopy=1`/arena cell
  via io_uring_write_zerocopy) pass under build-dev-asan, ASan-clean -- 6/6.
  Recipe: `cd tests && ./autest.sh --ats-bin=/tmp/ats-dev-asan/bin --sandbox=/tmp/sb --filters='io_uring_*'`.
  FORCE-ON DIFFERENTIAL DONE (flip RecordsConfig.cc `net.io_uring.enabled` 0->1 in a throwaway binary, run
  plain-HTTP gold tests, diff vs off). It FOUND A REAL BUG: a recv-destination-buffer write-after-free in
  `_read` (origin early-return drops the request-body buffer mid-recv -> kernel writes freed memory ->
  `ink_freelist_new "bad list"`). FIXED `bfb14a84ea` (pin destination blocks across the await); see
  [[io-uring-recv-buffer-uaf-freelist]]. post-early-return: crashed 3/3 on / clean off; plain-HTTP cases
  pass after the fix; io_uring_* suite still 6/6 ASan-clean.
  CAVEAT (cost me time): force-on globally ALSO breaks TLS ACCEPT -- the SSL acceptor builds plain io_uring
  VCs, TLS handshakes hang (curl "SSL connection timeout"). So the differential must skip ANY `enable_tls=True`
  test, not just tls//h2/ (post-early-return enables TLS yet its plain-HTTP cases are what matter). See
  [[io-uring-tls-depends-on-tls-refactor]].
  REMAINING: widen the force-on differential past the pilot set (basic/post/chunked/redirect done) to
  cache/timeout/headers/tunnel/pipeline -- ASan + autest parallelism makes fixed-port tests (config family)
  collide and is slow; run sequential (`--jobs=1`) or curate. Diff against an enabled=0 run of the same set.

T2.3 **Master-TSan differential** (long-open task #13). Goal: confirm the io_uring net path adds no new
  data races. Recipe: TSan build (needs `sudo sysctl vm.mmap_rnd_bits=28`, jemalloc OFF), run the suite
  under load, triage by frame #0/#1 (NOT filename-anywhere); diff race classes vs a master TSan run
  (same infra races = pre-existing; see [[tls-refactor-prod-testing]]). Accept: no io_uring-specific race.

## TIER 3 -- the arena's production form (the +7%, currently a prototype)

T3.1 **Drop the global mutex** -- DONE (2026-06-28). Replaced `UringFixedBufArena`'s `std::mutex` +
  `std::vector` free-stack with a LOCK-FREE per-class `InkAtomicList` (ATS's ABA-safe Treiber stack, the
  same primitive `InkFreeList` is built on). At build() each class pre-creates one `RegisteredBufferData`
  per block, permanently bound to its block address, and pushes it onto the class list (linked via the
  `_flink` field at a runtime-computed offset). alloc()=pop, free()=push -- one CAS each, no lock.
  Counters are `std::atomic` relaxed; `_classes` is `std::unique_ptr<SizeClass[]>` (NOT vector --
  InkAtomicList + atomics are non-movable, and `new[]` gives the 16-byte alignment cmpxchg16b needs;
  a `static_assert(alignof(SizeClass)%16==0)` guards it). The refcount-gated recycle is preserved (the
  `_write` Ptr anchor holds the block until F_NOTIF, so free()/push can't fire mid-DMA).
  DECISION (asked, agreed 2026-06-28): atomic POOL only, NO per-thread magazine. ATS's thread-local
  magazine is `ProxyAllocator` (Thread.h members + THREAD_ALLOC), reserved for HOT allocators (~20 of
  ~95 ClassAllocators); cold allocators use the global atomic pool directly. The arena is cold (one
  alloc per >=64 KiB disk fragment), so it matches the cold-allocator convention -- the InkAtomicList
  IS the ClassAllocator global-pool layer done right. TODO(perf) left in the header for the magazine if
  it ever goes hot. Accept met: low alloc-rate path, this is correctness/scale not the number.
  VALIDATED: unit test test_iouring_arena 8 cases/302 assertions incl. an 8-thread×20k multi-class
  stamp/verify/free stress + pool-conservation drain -- green on dev + ASan + **TSan** (the only TSan
  race is the primitive's benign `_flink` link access in ink_atomiclist_pop/push, ABA-version-protected;
  added `race:ink_atomiclist_pop|push` to `.tsan_suppressions` next to the existing freelist entries --
  the arena is the first DIRECT InkAtomicList user, others go through ink_freelist). io_uring_* autests
  6/6 under ASan (write_zerocopy drives the arena under live net-thread concurrency). 9-agent adversarial
  review: lock-free correct, alignment concern refuted, no material findings.

T3.2 **IORING_REGISTER_CLONE_BUFFERS** (1x pinning). Goal: register the arena ONCE then clone into every
  ET_NET ring instead of independent per-ring registration (N x memlock). Kernel 6.12+ (box is 6.17);
  liburing helper may be absent -> raw `io_uring_register(ring_fd, IORING_REGISTER_CLONE_BUFFERS, &arg)`.
  Needs startup ordering (one ring registers first; others clone). Accept: 1x RLIMIT_MEMLOCK accounting;
  `send_zc_fixed` still works cross-thread (buf_index identical on all rings).

T3.3 **Size classes** -- DONE (2026-06-28). The single registered region is now partitioned into
  power-of-two size classes following the ATS IOBuffer size-index scheme (64K..top), so a read takes
  the smallest class that fits. ONE region still (== buffer index 0, all classes inside it), so
  `registered_index()` stays 0 and the send path / registration model are UNCHANGED -- the classes are
  purely an allocator-internal split (`UringFixedBufArena::build` carves per-class spans + free stacks).
  `fixed_arena_block_size` redefined as the TOP class (rounded down to an IOBuffer index, capped 2 MiB);
  default RAISED 1 MiB -> 2 MiB so a 1 MiB object's Doc (body + Doc struct + marshalled header > 1 MiB)
  lands in the 2 MiB class and engages send_zc_fixed under default config -- the headline bug from T2.1.
  Even-bytes split across classes; smallest-fitting only (NO upward promotion -- lending a big block to a
  small read would starve the large reads the arena exists for); exhausted/over-size both decline to heap
  and are counted. `RegisteredBufferData` carries an arena back-pointer + class id so free() returns the
  block to its owning class stack (decouples free() from the singleton -> unit-testable).
  METRICS (live): per-class `proxy.process.net.io_uring.fixed_arena.<64k|128k|256k|512k|1m|2m>.{alloc,
  free,in_use}` + arena-wide `fixed_arena.class_exhausted` + `fixed_arena.oversize_fallback`. These
  subsume the "silent over-size decline" visibility (no separate decline metric needed).
  TESTS: `src/iocore/io_uring/unit_tests/test_fixed_arena.cc` (Catch2 target `test_iouring_arena`, 6
  cases / 61 assertions): class selection (smallest fit incl. the 1 MiB-Doc -> 2M case), over-size
  decline (counted), exhaustion (counted) + recycle, distinct in-region non-overlapping blocks,
  registered_index==0, in-use accounting, disabled arena. Drives the allocator via a test-only ctor that
  skips records/registration/metrics. Build: `cmake --build build-dev --target test_iouring_arena`.
  NOTE: build()'s Note/Warning are diags()-guarded so the arena is constructible off-thread in tests.
  ORIGINAL goal text (kept for context): the arena had one fixed block size (wasted a block on medium
  objects, exhausted faster); add per-size slabs (powers of two up to the fragment size).
  PRIMARY DRIVER (found in T2.1): the single block_size is a hard CEILING -- any Doc bigger than
  block_size (body + `Doc` struct + marshalled header) makes `alloc()==nullptr`, silently falling back to
  a heap buffer (read still works; just no send_zc_fixed). With the default 1 MiB block a nominal 1 MiB
  object gets body+overhead > 1 MiB -> ZERO send_zc_fixed. So the arena's headline win is off by default
  config today.
  FRAMING (important, do not re-mis-state): this "whole Doc in one contiguous buffer" need is NOT new and
  is NOT an io_uring change -- the cache disk read has always done one `ink_aio_read` into one
  IOBufferData (CacheVC::handleRead), on epoll too. The normal allocator NEVER fails to size it:
  `iobuffer_size_to_index` rounds up to a power-of-two class (<= 2 MiB = MAX_BUFFER_SIZE_INDEX) and uses
  an exact xmalloc above that. The arena is the ONLY allocator that can be "too small", because it lacks
  size classes AND lacks that xmalloc escape. So mirror the normal allocator: per-size classes covering
  the fragment range, plus a path for Docs > the top class (either a top class >= the max fragment Doc,
  or fall through to heap by design -- but then count it).
  METRICS: add per-class alloc/free/in-use counters (and a class-exhausted + over-size-fallback counter).
  These subsume the "silent over-size decline" visibility, so no separate decline metric is needed before
  this lands (decided 2026-06-28).
  Accept: mixed-object workload doesn't exhaust the arena prematurely; small reads don't take big blocks;
  send_zc_fixed engages on 1 MiB objects with default config; per-class metrics move as expected.

T3.4 **Origin-recv coverage**. Goal: extend the fixed path past disk-served. Wire the origin/client recv
  MIOBuffer to allocate from the arena so pass-through (and RAM-hits of origin-fetched objects) become
  arena-backed too -- today only the disk-read Doc buffer is. Accept: `write_zerocopy_fixed` engages on
  a cache-miss pass-through large object, not just disk hits.

T3.5 **Arena ASan**. DONE -- folded into T2.1's io_uring_write_zerocopy autest run under build-dev-asan.
  The wrk round-robin load drove ~4.5k send_zc_fixed (4581) through the arena -- thousands of block
  alloc/recycle cycles -- and the abort-mid-read phase closed connections while a send_zc + NOTIF were
  in flight (the cancel/teardown -> _complete_deferred_close path), all ASan-clean (detect_leaks=0,
  halt_on_error=1): no UAF on a recycled block reused before its NOTIF. The arena memory is mmap'd and
  intentionally never freed (NO_ALLOC), so leak detection is off; the gate here is use-after-free, which
  the recycle path could trip and did not. NOTE if re-running with leaks on: the arena region + idle
  descriptors will show as "leaks" by design.

## Suggested order

DONE: T2.1 + T3.5 + T2.2 io_uring-suite cell + T2.2 force-on pilot (recv UAF, bfb14a84ea) + T3.3 (size
classes) + T3.1 (lock-free InkAtomicList pool) + T3.4 (recv coalescing for pass-through send-ZC -- built,
measured, NO-GO for general prod: needs a high lowat unsafe for TLS/H2, moot for H2 by the framing copy;
renamed recv_zerocopy->recv_coalesce, off by default) + **PERF MILESTONE** (disk-cache serving step
ladder, master epoll+thread-AIO 0.341 -> io_uring+arena+send_zc_fixed 0.132 = -61% cpu/1k, true NIC ZC;
recorded in experiments/coro-net-prototype/PERF-RESULTS-2026-06-28.md = canonical store, see
[[io-uring-perf-results]]) + widened T2.2 force-on differential under ASan (0 UAF in 9 plain-HTTP tests,
but FOUND a ship-blocker, below).

NEXT (Track B = bank the proven win toward shipping):
1. **The io_uring "pipelining stall" is RESOLVED** -- it was mis-titled, NOT a read-path re-signal bug.
   The `_read` re-signal hypothesis was disproved via a literal-IP-remap differential (pipelining
   works). Real cause: io_uring net threads block in the ring and never poll their epoll-registered
   DNS UDP sockets, so async DNS (hostname remaps) hung at "Doing DNS Lookup". Fixed `4253f384c0`
   (IOUringPollBridge multishot-polls the thread's epoll fd into the ring + non-blocking do_poll(0)
   harvest in waitForActivity); CI guard `e11d06b145` (io_uring_dns.test.py). See
   [[io-uring-pipelining-stall-bug]].
2. T2.3 master-TSan differential for the net path (the lock-free arena was already TSan-clean modulo
   the benign InkAtomicList race).
3. Widen the force-on differential further (more plain-HTTP autests, skip TLS).
4. T3.2 clone buffers (1x memlock).
5. Then scope the upstream PR (TLS-independent net path + arena -- TLS/H2 over io_uring is blocked on
   the TLS refactor, see [[io-uring-tls-depends-on-tls-refactor]]).

T3.6 **ZC disk read (read_fixed)** -- ON THE ROADMAP, LOW PRIORITY / LOW RISK (user, 2026-06-28). Use
io_uring_prep_read_fixed for the cache disk read into the already-registered arena block (read-side
mirror of send_zc_fixed) -> fully-registered round trip. Investigated+profiled 2026-06-28: gain is SMALL
(~0.07%) because the cache opens O_DIRECT so the read already DMAs disk->buffer with NO copy, and the
only thing read_fixed removes is the per-IO pin -- cheap because the arena is MAP_POPULATE pre-faulted
(get_user_pages = refcount bumps, not faults). BUT it's nearly-free + low-risk to wire (the buffer is
already registered for the send): plumb registered_index through the AIO op (AIOCallback), call the
arena's ensure_registered() before the read (the io_uring AIO read uses IOUringContext::local_context(),
AIO.cc:607 = the same per-thread ring the arena registers on, so buf_index 0 works), emit
io_uring_prep_read_fixed with a fallback to prep_read if unregistered. Take it when convenient for the
complete picture; an upstream reviewer would question AIO-subsystem complexity for 0.07%.
