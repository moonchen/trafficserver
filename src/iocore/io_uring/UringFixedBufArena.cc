/** @file

  A process-global, io_uring-registered ("fixed") buffer arena. See the header.

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

#include "iocore/io_uring/UringFixedBufArena.h"

#if TS_USE_LINUX_IO_URING

#include "iocore/io_uring/IO_URING.h"
#include "records/RecCore.h"
#include "tscore/Diags.h"
#include "tscore/ink_assert.h"

#include <cinttypes>
#include <string>
#include <sys/mman.h>

using ts::Metrics;

namespace
{
DbgCtl dbg_ctl_fixed_arena{"io_uring_arena"};

// Clone-source election for the arena's fixed-buffer registration. -1 = unclaimed, -2 = a thread
// is registering (source not published yet), >= 0 = the source ring fd others clone from. One
// thread registers the pinned region on its ring and publishes its fd; the rest clone from it
// (IORING_REGISTER_CLONE_BUFFERS) so the region is pinned 1x, not once per ring. A thread that
// arrives during the tiny -2 window, or whose clone fails, falls back to an independent
// registration -- correct, just not memlock-shared, so the worst case is the old N-x behavior.
std::atomic<int> arena_clone_src_fd{-1};

// The smallest size class the arena offers. The cache only draws from the arena for reads >=
// 64 KiB (CacheVC::handleRead), so a 64 KiB floor wastes nothing on tiny reads. Classes run
// from here up to a configurable top (<= 2 MiB = MAX_BUFFER_SIZE_INDEX), following the ATS
// IOBuffer power-of-two size-index scheme so a class id is the IOBuffer size index.
constexpr int MIN_ARENA_INDEX = BUFFER_SIZE_INDEX_64K;
constexpr int MAX_CLASSES     = MAX_BUFFER_SIZE_INDEX - MIN_ARENA_INDEX + 1;

int64_t
index_block_size(int idx)
{
  return int64_t{DEFAULT_BUFFER_BASE_SIZE} << idx; // 128 << idx
}

// "64k", "128k", "1m", "2m" -- the per-class metric name component.
std::string
class_label(unsigned block_size)
{
  if (block_size >= (1u << 20)) {
    return std::to_string(block_size >> 20) + "m";
  }
  return std::to_string(block_size >> 10) + "k";
}
} // namespace

UringFixedBufArena &
UringFixedBufArena::instance()
{
  static UringFixedBufArena arena;
  return arena;
}

UringFixedBufArena::UringFixedBufArena()
{
  int64_t total = RecGetRecordInt("proxy.config.net.io_uring.fixed_arena_size").value_or(0);
  // fixed_arena_block_size is the largest size class (rounded down to a power-of-two IOBuffer
  // index, capped at 2 MiB). It used to be the ONE block size, which silently declined any Doc
  // bigger than it -- a nominal 1 MiB object (1 MiB body + Doc header) needs the 2 MiB class.
  int64_t bsz = RecGetRecordInt("proxy.config.net.io_uring.fixed_arena_block_size").value_or(2097152);
  build(total, bsz, /* with_metrics */ true);
}

UringFixedBufArena::UringFixedBufArena(int64_t total_bytes, int64_t max_block_size)
{
  build(total_bytes, max_block_size, /* with_metrics */ false);
}

void
UringFixedBufArena::build(int64_t total_bytes, int64_t max_block_size, bool with_metrics)
{
  if (total_bytes <= 0 || max_block_size <= 0) {
    return; // disabled (default: fixed_arena_size == 0)
  }

  // Top class: the largest IOBuffer index whose block size is <= the configured max (and <= the
  // 2 MiB allocator ceiling). Mirrors iobuffer_size_to_index's power-of-two classes.
  int top = -1;
  for (int i = MIN_ARENA_INDEX; i <= MAX_BUFFER_SIZE_INDEX; ++i) {
    if (index_block_size(i) <= max_block_size) {
      top = i;
    } else {
      break;
    }
  }
  if (top < MIN_ARENA_INDEX) {
    if (diags() != nullptr) {
      Warning("io_uring fixed arena: fixed_arena_block_size=%" PRId64 " is below the %" PRId64 " B floor; disabled", max_block_size,
              index_block_size(MIN_ARENA_INDEX));
    }
    return;
  }

  // Even-bytes split: each class gets total/nclasses bytes, floored to a whole number of blocks. So
  // full coverage (>=1 block in every class, including the top one) needs total >= nclasses * top
  // block size (~12 MiB at the default 2 MiB top, 6 classes); below that the loop below warns.
  const int     nclasses  = top - MIN_ARENA_INDEX + 1;
  const int64_t per_class = total_bytes / nclasses;

  unsigned nblocks[MAX_CLASSES]  = {};
  size_t   base_off[MAX_CLASSES] = {};
  size_t   off                   = 0;
  for (int ci = 0; ci < nclasses; ++ci) {
    const int64_t bs  = index_block_size(MIN_ARENA_INDEX + ci);
    nblocks[ci]       = static_cast<unsigned>(per_class / bs);
    base_off[ci]      = off;
    off              += static_cast<size_t>(nblocks[ci]) * bs;
  }
  if (off == 0) {
    if (diags() != nullptr) {
      Warning("io_uring fixed arena: fixed_arena_size=%" PRId64 " too small for any block; disabled", total_bytes);
    }
    return;
  }

  // Page-aligned, pre-faulted region; the io_uring registration pins it.
  void *p = mmap(nullptr, off, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  if (p == MAP_FAILED) {
    if (diags() != nullptr) {
      Warning("io_uring fixed arena: mmap(%zu) failed; disabled", off);
    }
    return;
  }
  _region     = static_cast<char *>(p);
  _region_len = off;
  _nclasses   = static_cast<size_t>(nclasses);
  _classes    = std::make_unique<SizeClass[]>(_nclasses);

  // Byte offset of the intrusive freelist link within the (polymorphic) descriptor, computed the
  // same way ATS computes InkAtomicList offsets elsewhere (a sample instance, not offsetof).
  RegisteredBufferData probe;
  const uint32_t flink_off = static_cast<uint32_t>(reinterpret_cast<char *>(&probe._flink) - reinterpret_cast<char *>(&probe));

  std::string summary;
  for (int ci = 0; ci < nclasses; ++ci) {
    SizeClass &c = _classes[ci];
    c.block_size = static_cast<unsigned>(index_block_size(MIN_ARENA_INDEX + ci));
    c.size_index = MIN_ARENA_INDEX + ci;
    c.nblocks    = nblocks[ci];
    ink_atomiclist_init(&c.free_list, "UringFixedBufArena", flink_off);

    // One descriptor per block, permanently bound to its block address and pushed onto the
    // class's lock-free free list. alloc() pops; free() pushes the same descriptor back.
    for (unsigned b = 0; b < c.nblocks; ++b) {
      auto *d        = new RegisteredBufferData();
      d->_arena      = this;
      d->_class_id   = static_cast<unsigned>(ci);
      d->_block_idx  = b;
      d->_buf_index  = 0; // the single registered region
      d->_data       = _region + base_off[ci] + static_cast<size_t>(b) * c.block_size;
      d->_size_index = c.size_index;
      d->_mem_type   = NO_ALLOC; // dealloc() (never reached, free() is overridden) must not free it
      ink_atomiclist_push(&c.free_list, d);
    }

    if (with_metrics) {
      const std::string base = "proxy.process.net.io_uring.fixed_arena." + class_label(c.block_size) + ".";
      c.alloc_stat           = Metrics::Counter::createPtr(base + "alloc");
      c.free_stat            = Metrics::Counter::createPtr(base + "free");
      c.inuse_gauge          = Metrics::Gauge::createPtr(base + "in_use");
    }
    // The even-bytes split gives each class total/nclasses bytes; if that is below a class's block
    // size the class gets zero blocks and silently declines every request for that size (-> heap, no
    // send_zc_fixed). Warn so an operator who under-sized the arena sees it instead of an arena that
    // is "enabled" but does nothing for large objects. Full coverage needs nclasses * top_block_size.
    if (c.nblocks == 0 && diags() != nullptr) {
      Warning("io_uring fixed arena: class %s got 0 blocks; raise fixed_arena_size to >= %" PRId64 " for full coverage",
              class_label(c.block_size).c_str(), static_cast<int64_t>(nclasses) * index_block_size(top));
    }
    summary += " " + class_label(c.block_size) + ":" + std::to_string(c.nblocks);
  }
  if (with_metrics) {
    _exhausted_stat = Metrics::Counter::createPtr("proxy.process.net.io_uring.fixed_arena.class_exhausted");
    _oversize_stat  = Metrics::Counter::createPtr("proxy.process.net.io_uring.fixed_arena.oversize_fallback");
  }
  if (diags() != nullptr) {
    Note("io_uring fixed arena: %zu MB pinned, blocks/class:%s", _region_len >> 20, summary.c_str());
  }
}

void
UringFixedBufArena::ensure_registered()
{
  if (_region == nullptr) {
    return;
  }
  // The single region (== buffer index 0) is registered on one ring and cloned into the others, so
  // all rings share one pinned copy. All size classes live within this region, so send_zc_fixed
  // addresses any block by index 0 no matter which ring cloned it.
  static thread_local bool registered = false;
  if (registered) {
    return;
  }
  registered = true;
  auto *ctx  = IOUringContext::local_context();

  // Elect a single clone source: the first thread here registers the region and publishes its ring
  // fd; everyone else clones from it (1x pin). CAS -1 -> -2 claims the source role.
  int expected = -1;
  if (arena_clone_src_fd.compare_exchange_strong(expected, -2, std::memory_order_acq_rel)) {
    int rc = ctx->register_fixed_buffers(_region, _region_len);
    if (rc < 0) {
      Warning("io_uring fixed arena: register_buffers failed (%d) on the source ring", rc);
      arena_clone_src_fd.store(-1, std::memory_order_release); // release the role; let another try
      return;
    }
    arena_clone_src_fd.store(ctx->ring_fd(), std::memory_order_release); // publish: clones may proceed
    Dbg(dbg_ctl_fixed_arena, "fixed arena: registered as the clone source (ring fd %d)", ctx->ring_fd());
    return;
  }

  // Not the source. Clone from it if it is ready; otherwise register independently (safe fallback).
  if (int src = arena_clone_src_fd.load(std::memory_order_acquire); src >= 0 && ctx->clone_fixed_buffers(src) == 0) {
    Dbg(dbg_ctl_fixed_arena, "fixed arena: cloned registration from source ring fd %d", src);
    return; // shares the source's pinned pages -- no extra memlock
  }
  // src still registering (-2), or clone unsupported/failed: independent registration (old path).
  int rc = ctx->register_fixed_buffers(_region, _region_len);
  if (rc < 0) {
    Warning("io_uring fixed arena: register_buffers failed (%d) on this ring", rc);
  } else {
    Dbg(dbg_ctl_fixed_arena, "fixed arena: independent registration (clone source not ready / unsupported)");
  }
}

RegisteredBufferData *
UringFixedBufArena::alloc(int64_t req_bytes)
{
  if (_region == nullptr || req_bytes <= 0) {
    return nullptr;
  }

  // Smallest class that fits. _classes is ascending, so the first fit is the smallest. No upward
  // promotion on exhaustion: lending a bigger block to a small read would starve the large reads
  // the arena exists to serve.
  size_t ci = _nclasses;
  for (size_t i = 0; i < _nclasses; ++i) {
    if (static_cast<int64_t>(_classes[i].block_size) >= req_bytes) {
      ci = i;
      break;
    }
  }
  if (ci == _nclasses) {
    _oversize.fetch_add(1, std::memory_order_relaxed); // larger than the top class -> heap fallback
    if (_oversize_stat != nullptr) {
      Metrics::Counter::increment(_oversize_stat);
    }
    return nullptr;
  }

  SizeClass &c = _classes[ci];
  auto      *d = static_cast<RegisteredBufferData *>(ink_atomiclist_pop(&c.free_list)); // lock-free
  if (d == nullptr) {
    _exhausted.fetch_add(1, std::memory_order_relaxed);
    if (_exhausted_stat != nullptr) {
      Metrics::Counter::increment(_exhausted_stat);
    }
    return nullptr;
  }
  // The descriptor's block binding (_data / _size_index / _buf_index / _class_id) is permanent; the
  // only stale field is _flink (its old free-list link), which is unused while the block is in use.
  c.n_alloc.fetch_add(1, std::memory_order_relaxed);
  if (c.alloc_stat != nullptr) {
    Metrics::Counter::increment(c.alloc_stat);
    Metrics::Gauge::increment(c.inuse_gauge);
  }
  return d;
}

void
UringFixedBufArena::release(unsigned class_id, RegisteredBufferData *desc)
{
  ink_assert(class_id < _nclasses); // only reached via free() on a descriptor alloc() handed out
  SizeClass &c = _classes[class_id];
  ink_atomiclist_push(&c.free_list, desc); // lock-free
  c.n_free.fetch_add(1, std::memory_order_relaxed);
  if (c.free_stat != nullptr) {
    Metrics::Counter::increment(c.free_stat);
    Metrics::Gauge::decrement(c.inuse_gauge);
  }
}

void
RegisteredBufferData::free()
{
  // The descriptor keeps its block binding for the next alloc; just return it to its class pool.
  ink_assert(_arena != nullptr); // every pooled descriptor is bound to its arena at build()
  _arena->release(_class_id, this);
}

#endif // TS_USE_LINUX_IO_URING
