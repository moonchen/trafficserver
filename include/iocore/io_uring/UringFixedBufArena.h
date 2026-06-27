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
// PROTOTYPE scope (to measure the win before the full build-out): one region == registered
// buffer index 0, one fixed block size, a single mutex-guarded free-block stack, and
// independent per-ring registration (N x memlock). Production refinements, noted inline:
//   - per-thread DRAINABLE magazines over a global pool (ClassAllocator semantics),
//   - IORING_REGISTER_CLONE_BUFFERS (register once, clone into the other rings -> 1x pin).
class RegisteredBufferData;

class UringFixedBufArena
{
public:
  static UringFixedBufArena &instance();

  bool
  enabled() const
  {
    return _region != nullptr;
  }
  unsigned
  block_size() const
  {
    return _block_size;
  }

  // Register the arena on the current thread's ring (idempotent per thread). Must run on a
  // net thread before it issues send_zc_fixed from an arena block.
  void ensure_registered();

  // A free block wrapped as a RegisteredBufferData sized to req_bytes (<= block_size), or
  // nullptr if disabled / exhausted (caller falls back to new_IOBufferData -> copy send).
  RegisteredBufferData *alloc(int64_t req_bytes);

  // Recycle a block + its descriptor (called from RegisteredBufferData::free()).
  void release(uint32_t block_idx, RegisteredBufferData *desc);

private:
  UringFixedBufArena();
  void init();

  char    *_region     = nullptr;
  size_t   _region_len = 0;
  unsigned _block_size = 0;
  unsigned _nblocks    = 0;

  std::mutex            _m;
  std::vector<uint32_t> _free_blocks;         // guarded by _m (prototype: global stack)
  RegisteredBufferData *_free_desc = nullptr; // descriptor freelist, guarded by _m
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

  uint32_t              _block_idx = 0;
  int                   _buf_index = -1;
  RegisteredBufferData *_flink     = nullptr; // descriptor freelist link while idle
};

#endif // TS_USE_LINUX_IO_URING
