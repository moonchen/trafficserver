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

T2.1 **Large-object zero-copy autest** (Tier-1 tail). Goal: gold test for a disk-served large-object
  zero-copy serve + teardown-with-send-in-flight. Files: new `tests/gold_tests/.../*.test.py` + a
  client that aborts mid-1 MiB-read (close while a send_zc + NOTIF are in flight). Accept: body intact
  + no crash with `write_zerocopy=1`; runs under OpenSSL+ASAN. Gotcha: needs a disk cache + the
  round-robin trick to actually hit the ZC path; verify the `write_zerocopy` metric increments in-test.

T2.2 **Full autest suite + ASan** with `io_uring.enabled=1` (and a cell with `write_zerocopy=1`).
  Accept: no NEW failures vs master (pre-existing fails are catalogued in [[tls-refactor-fullsuite-regressions]]
  style -- compare against an `enabled=0` run). Recipe: `autest.sh -R iouring ...` + distinct
  `AUTEST_PORT_OFFSET` if concurrent (see [[autest-concurrent-port-offset]]).

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

T3.4 **Origin-recv coverage**. Goal: extend the fixed path past disk-served. Wire the origin/client recv
  MIOBuffer to allocate from the arena so pass-through (and RAM-hits of origin-fetched objects) become
  arena-backed too -- today only the disk-read Doc buffer is. Accept: `write_zerocopy_fixed` engages on
  a cache-miss pass-through large object, not just disk hits.

T3.5 **Arena ASan**. Goal: validate the arena recycle/teardown lifetime (the NEW, riskiest code) under
  ASan -- a disk-read arena workload (round-robin) + connection churn + mid-write aborts, with
  `fixed_arena_size>0`. Accept: ASan-clean (no UAF on a recycled block reused before its NOTIF). This is
  the gate before the arena is trustworthy under load; do it EARLY in Tier 3.

## Suggested order

T3.5 (arena ASan -- safety first) -> T3.1 (magazines) -> T2.1+T2.2 (autests) -> T3.2/T3.3/T3.4 (breadth)
-> T2.3 (TSan). Ship sequence stays: batching first, then large-object zero-copy (anon), then the arena.
