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
  PARTIAL: all 6 `io_uring_*` gold tests (which set `enabled=1` themselves, and now a `write_zerocopy=1`
  + arena cell via io_uring_write_zerocopy) pass under build-dev-asan, ASan-clean -- 6/6.
  Recipe: `cd tests && ./autest.sh --ats-bin=/tmp/ats-dev-asan/bin --sandbox=/tmp/sb --filters='io_uring_*'`.
  REMAINING: force io_uring on for the WHOLE suite to catch general-proxying regressions -- the per-test
  records_config can't be overridden globally, so this needs either a default flip in RecordsConfig.cc
  (`net.io_uring.enabled` 0->1) rebuilt into a throwaway binary, then a full-suite run diffed against an
  enabled=0 run; or a representative subset (basic/cache/h2/post/redirect/tunnel) re-run with the flip.
  Distinct `AUTEST_PORT_OFFSET` only if running concurrent autest.sh (see [[autest-concurrent-port-offset]]).

T2.3 **Master-TSan differential** (long-open task #13). Goal: confirm the io_uring net path adds no new
  data races. Recipe: TSan build (needs `sudo sysctl vm.mmap_rnd_bits=28`, jemalloc OFF), run the suite
  under load, triage by frame #0/#1 (NOT filename-anywhere); diff race classes vs a master TSan run
  (same infra races = pre-existing; see [[tls-refactor-prod-testing]]). Accept: no io_uring-specific race.

## TIER 3 -- the arena's production form (the +7%, currently a prototype)

T3.1 **Per-thread drainable magazines** (drop the global mutex). Goal: replace `UringFixedBufArena`'s
  `std::mutex` + `std::vector` free-stack with `InkFreeList`/`ClassAllocator`-style per-thread magazines
  over a global pool (ATS already has this: `thread_freelist_size`=512 cap + `_low_watermark`=32 refill).
  The catch: the arena MEMORY is a fixed registered mmap region, so give the freelist a custom chunk
  source (the region) instead of `ats_memalign`. Accept: same cpu/1k on the large-obj A/B (it's a low
  alloc-rate path so this is correctness/scale, not the number); validates under churn. Gotcha:
  refcount-gated recycle must be preserved (block not reused until F_NOTIF; the `_write` anchor holds it).

T3.2 **IORING_REGISTER_CLONE_BUFFERS** (1x pinning). Goal: register the arena ONCE then clone into every
  ET_NET ring instead of independent per-ring registration (N x memlock). Kernel 6.12+ (box is 6.17);
  liburing helper may be absent -> raw `io_uring_register(ring_fd, IORING_REGISTER_CLONE_BUFFERS, &arg)`.
  Needs startup ordering (one ring registers first; others clone). Accept: 1x RLIMIT_MEMLOCK accounting;
  `send_zc_fixed` still works cross-thread (buf_index identical on all rings).

T3.3 **Size classes**. Goal: the arena currently has one fixed block size (wastes a block on medium
  objects, exhausts faster). Add per-size slabs (e.g. powers of two up to the fragment size). Accept:
  mixed-object workload doesn't exhaust the arena prematurely; small reads don't take big blocks.
  EXTRA MOTIVATION (found in T2.1): the single block_size is also a hard CEILING -- any Doc bigger than
  block_size (body + Doc struct + marshalled header) gets `alloc()==nullptr` and falls back to heap (no
  ZC), silently. So with the default 1 MiB block, a 1 MiB object never uses send_zc_fixed. Size classes
  (or just a bigger top class) must cover the largest fragment's full Doc, not just the body.

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

DONE: T2.1 (zero-copy autest) + T3.5 (arena ASan, folded in) + T2.2 io_uring-suite cell (6/6 ASan-clean).
REMAINING: T3.1 (magazines) -> T3.3/T3.2/T3.4 (arena breadth; T3.3 now has a concrete bug-shaped driver)
-> T2.2 full-suite global-on differential -> T2.3 (TSan). Ship sequence stays: batching first, then
large-object zero-copy (anon), then the arena.
