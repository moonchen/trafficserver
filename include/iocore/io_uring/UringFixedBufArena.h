/** @file

  A process-global, io_uring-registered ("fixed") buffer arena.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#pragma once

#include "tscore/ink_config.h"

#if TS_USE_LINUX_IO_URING

#include "iocore/eventsystem/IOBuffer.h"
#include "tscore/ink_queue.h"
#include "tsutil/Metrics.h"
#include <atomic>
#include <cstdint>
#include <memory>

// Process-global, io_uring-registered ("fixed") buffer arena. The region is pinned and
// registered on every ET_NET thread's ring, so send_zc_fixed can DMA from any block no
// matter which thread filled it (the cache is shared across threads). Blocks recycle on
// free; the memory outlives every VC / cache entry.
//
// The single registered region is partitioned into power-of-two SIZE CLASSES following the
// ATS IOBuffer size-index scheme (64K..2M): a read takes the smallest class that fits, which
// mirrors how the normal allocator (iobuffer_size_to_index) rounds a Doc up to a power-of-two
// class. This matters because the arena is the only allocator that can be "too small": alloc()
// declines (silently, falling back to heap blocks and plain sends) whenever no class fits, so
// the classes must span the whole disk-fragment size range or oversized Docs never get
// send_zc_fixed. The classes share ONE registered region (== buffer index 0), so
// registered_index() is 0 for every block and the send path is unchanged -- the classes are
// purely an allocator-internal split.
//
// Each class is a LOCK-FREE pool: an InkAtomicList (ATS's ABA-safe Treiber stack) of descriptors
// pre-bound to blocks. alloc() pops, free() pushes -- one CAS each, no mutex. This is the same
// global-pool layer ATS's ClassAllocator uses (an atomic InkFreeList). ATS adds a per-thread
// ProxyAllocator magazine in front of that ONLY for hot allocators (~20 of ~95); this arena is a
// cold allocator (one alloc per >=64 KiB disk fragment), so it uses the atomic pool directly.
// TODO(perf): if the arena ever goes hot, add a ProxyAllocator-style thread-local magazine
//   (thread_freelist_high/low_watermark) over these per-class pools.
// The region is pinned once: one ring registers it and the rest clone that registration
// (IORING_REGISTER_CLONE_BUFFERS), so RLIMIT_MEMLOCK accounts the region 1x, not once per ring.
class RegisteredBufferData;

class UringFixedBufArena
{
public:
  static UringFixedBufArena &instance();

  // Test-only: build the size-class table + backing region from explicit parameters, skipping
  // records, io_uring registration, and metrics. Production uses instance() (records-driven).
  UringFixedBufArena(int64_t total_bytes, int64_t max_block_size);

  bool
  enabled() const
  {
    return _region != nullptr;
  }

  // The smallest size class the arena offers (== the 64 KiB IOBuffer class). Requests below it
  // are not worth an arena block; callers (CacheVC::handleRead) gate their draw on this floor.
  static constexpr int64_t MIN_BLOCK_SIZE = int64_t{DEFAULT_BUFFER_BASE_SIZE} << BUFFER_SIZE_INDEX_64K;

  // Register the arena on the current thread's ring, returning whether this ring now has the
  // registration (success is cached per thread; failure is retried on the next call). A net
  // thread must see true before it issues send_zc_fixed from an arena block -- on false (e.g.
  // RLIMIT_MEMLOCK) the caller must stay on the anonymous/copy send path.
  bool ensure_registered();

  // A free block wrapped as a RegisteredBufferData drawn from the smallest size class that fits
  // req_bytes, or nullptr if disabled / the request exceeds the top class (over-size) / the
  // fitting class is exhausted (caller falls back to new_IOBufferData -> copy send). The decline
  // reasons are visible in the oversize / class-exhausted metrics.
  RegisteredBufferData *alloc(int64_t req_bytes);

  // Recycle a block + its descriptor (called from RegisteredBufferData::free()).
  void release(unsigned class_id, RegisteredBufferData *desc);

  // Introspection for tests and ops. Counters are atomic; the per-class block tables are
  // immutable after build().
  size_t
  num_classes() const
  {
    return _nclasses;
  }
  unsigned
  class_block_size(size_t i) const
  {
    return _classes[i].block_size;
  }
  unsigned
  class_nblocks(size_t i) const
  {
    return _classes[i].nblocks;
  }
  int64_t
  class_alloc(size_t i) const
  {
    return _classes[i].n_alloc.load(std::memory_order_relaxed);
  }
  // Approximate under concurrency (two relaxed loads, not a consistent snapshot); exact once the
  // allocating threads have quiesced, which is how tests and ops snapshots read it.
  int64_t
  class_in_use(size_t i) const
  {
    return _classes[i].n_alloc.load(std::memory_order_relaxed) - _classes[i].n_free.load(std::memory_order_relaxed);
  }
  int64_t
  exhausted_count() const
  {
    return _exhausted.load(std::memory_order_relaxed);
  }
  int64_t
  oversize_count() const
  {
    return _oversize.load(std::memory_order_relaxed);
  }
  const char *
  region_base() const
  {
    return _region;
  }
  size_t
  region_len() const
  {
    return _region_len;
  }

private:
  UringFixedBufArena();
  void build(int64_t total_bytes, int64_t max_block_size, bool with_metrics);

  // One power-of-two block size carved from a contiguous span of the single region. Its free
  // blocks live as pre-bound descriptors on a lock-free InkAtomicList (linked via _flink).
  struct SizeClass {
    unsigned      block_size = 0; // bytes per block (power of two, 64K..2M)
    int           size_index = 0; // ATS IOBuffer size index for block_size (== class id)
    unsigned      nblocks    = 0;
    InkAtomicList free_list; // lock-free stack of free RegisteredBufferData (linked by _flink)

    std::atomic<int64_t> n_alloc{0};
    std::atomic<int64_t> n_free{0};

    ts::Metrics::Counter::AtomicType *alloc_stat  = nullptr;
    ts::Metrics::Counter::AtomicType *free_stat   = nullptr;
    ts::Metrics::Gauge::AtomicType   *inuse_gauge = nullptr;
  };
  // InkAtomicList::head is a 128-bit value (cmpxchg16b on x86-64) and must be 16-byte aligned;
  // head_p drives SizeClass's alignment, and new SizeClass[] honors it. Fail loud if a future
  // field reshuffle ever breaks that contract.
  static_assert(alignof(SizeClass) % 16 == 0, "InkAtomicList head needs 16-byte alignment for cmpxchg16b");

  char  *_region     = nullptr;
  size_t _region_len = 0;

  std::unique_ptr<SizeClass[]> _classes; // _nclasses entries, ascending block_size, immutable after build
  size_t                       _nclasses = 0;

  std::atomic<int64_t> _exhausted{0}; // requests that hit an empty fitting class
  std::atomic<int64_t> _oversize{0};  // requests larger than the top class

  ts::Metrics::Counter::AtomicType *_exhausted_stat = nullptr;
  ts::Metrics::Counter::AtomicType *_oversize_stat  = nullptr;
};

// IOBufferData backed by one arena block. free() recycles the block + descriptor instead of
// releasing memory (the arena owns the pinned memory for the process lifetime). Each descriptor
// is permanently bound to one block at build() time. Because IOBufferBlock::clone() shares the
// Ptr<IOBufferData>, a block handed to several readers recycles only once, when the last ref
// drops -- and the write anchor holds a ref until the F_NOTIF, so an in-flight block is never
// recycled while the NIC is still DMA-ing it.
class RegisteredBufferData : public IOBufferData
{
public:
  void free() override;
  int
  registered_index() const override
  {
    return _buf_index;
  }

  UringFixedBufArena   *_arena     = nullptr; // owning arena, so free() returns to the right pool
  uint32_t              _block_idx = 0;       // ordinal within its size class (diagnostics)
  unsigned              _class_id  = 0;       // index into _arena->_classes
  int                   _buf_index = -1;      // registered region index (0 when arena-backed)
  RegisteredBufferData *_flink     = nullptr; // intrusive next while on a class's free list
};

#endif // TS_USE_LINUX_IO_URING
