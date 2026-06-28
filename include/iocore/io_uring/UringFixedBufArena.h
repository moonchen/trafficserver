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
#include "tsutil/Metrics.h"
#include <mutex>
#include <vector>
#include <cstdint>

// Process-global, io_uring-registered ("fixed") buffer arena. The region is pinned and
// registered on every ET_NET thread's ring, so send_zc_fixed can DMA from any block no
// matter which thread filled it (the cache is shared across threads). Blocks recycle on
// free; the memory outlives every VC / cache entry. Allocation is what stays "share
// nothing" -- the memory is necessarily global (registered everywhere) but the alloc/free
// path is per-thread-cacheable.
//
// The single registered region is partitioned into power-of-two SIZE CLASSES following the
// ATS IOBuffer size-index scheme (64K..2M): a read takes the smallest class that fits, which
// mirrors how the normal allocator (iobuffer_size_to_index) rounds a Doc up to a power-of-two
// class. This matters because the arena is the only allocator that can be "too small": a Doc
// larger than the one block size used to make alloc() decline silently (no send_zc_fixed). The
// classes share ONE registered region (== buffer index 0), so registered_index() is 0 for every
// block and the send path is unchanged -- the classes are purely an allocator-internal split.
//
// PROTOTYPE scope still open (production refinements, noted inline):
//   - per-thread DRAINABLE magazines over a global pool (drop the single mutex; ClassAllocator),
//   - IORING_REGISTER_CLONE_BUFFERS (register once, clone into the other rings -> 1x pin).
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

  // Register the arena on the current thread's ring (idempotent per thread). Must run on a
  // net thread before it issues send_zc_fixed from an arena block.
  void ensure_registered();

  // A free block wrapped as a RegisteredBufferData drawn from the smallest size class that fits
  // req_bytes, or nullptr if disabled / the request exceeds the top class (over-size) / the
  // fitting class is exhausted (caller falls back to new_IOBufferData -> copy send). The decline
  // reasons are visible in the oversize / class-exhausted metrics.
  RegisteredBufferData *alloc(int64_t req_bytes);

  // Recycle a block + its descriptor (called from RegisteredBufferData::free()).
  void release(unsigned class_id, uint32_t block_idx, RegisteredBufferData *desc);

  // Introspection for tests and ops. The counters are written under the arena mutex; these
  // unlocked reads are a racy-but-monotonic snapshot (tests are single-threaded).
  size_t
  num_classes() const
  {
    return _classes.size();
  }
  unsigned
  class_block_size(size_t i) const
  {
    return _classes[i].block_size;
  }
  int64_t
  class_alloc(size_t i) const
  {
    return _classes[i].n_alloc;
  }
  int64_t
  class_in_use(size_t i) const
  {
    return _classes[i].n_alloc - _classes[i].n_free;
  }
  int64_t
  exhausted_count() const
  {
    return _exhausted;
  }
  int64_t
  oversize_count() const
  {
    return _oversize;
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

  // One power-of-two block size carved from a contiguous span of the single region.
  struct SizeClass {
    unsigned              block_size = 0; // bytes per block (power of two, 64K..2M)
    int                   size_index = 0; // ATS IOBuffer size index for block_size (== class id)
    size_t                base_off   = 0; // byte offset of this class's span within _region
    unsigned              nblocks    = 0;
    std::vector<uint32_t> free;        // free block ordinals [0,nblocks), guarded by _m
    int64_t               n_alloc = 0; // guarded by _m
    int64_t               n_free  = 0; // guarded by _m

    ts::Metrics::Counter::AtomicType *alloc_stat  = nullptr;
    ts::Metrics::Counter::AtomicType *free_stat   = nullptr;
    ts::Metrics::Gauge::AtomicType   *inuse_gauge = nullptr;
  };

  char  *_region     = nullptr;
  size_t _region_len = 0;

  std::mutex             _m;
  std::vector<SizeClass> _classes;             // ascending block_size, guarded by _m
  RegisteredBufferData  *_free_desc = nullptr; // descriptor freelist, guarded by _m
  int64_t                _exhausted = 0;       // requests that hit an empty fitting class (guarded by _m)
  int64_t                _oversize  = 0;       // requests larger than the top class (guarded by _m)

  ts::Metrics::Counter::AtomicType *_exhausted_stat = nullptr;
  ts::Metrics::Counter::AtomicType *_oversize_stat  = nullptr;
};

// IOBufferData backed by one arena block. free() recycles the block + descriptor instead of
// releasing memory (the arena owns the pinned memory for the process lifetime). Because
// IOBufferBlock::clone() shares the Ptr<IOBufferData>, a block handed to several readers
// recycles only once, when the last ref drops -- and the write anchor holds a ref until the
// F_NOTIF, so an in-flight block is never recycled while the NIC is still DMA-ing it.
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
  uint32_t              _block_idx = 0;       // ordinal within its size class
  unsigned              _class_id  = 0;       // index into _arena->_classes
  int                   _buf_index = -1;      // registered region index (0 when arena-backed)
  RegisteredBufferData *_flink     = nullptr; // descriptor freelist link while idle
};

#endif // TS_USE_LINUX_IO_URING
