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

#include <sys/mman.h>

UringFixedBufArena &
UringFixedBufArena::instance()
{
  static UringFixedBufArena arena;
  return arena;
}

UringFixedBufArena::UringFixedBufArena()
{
  init();
}

void
UringFixedBufArena::init()
{
  int64_t total = RecGetRecordInt("proxy.config.net.io_uring.fixed_arena_size").value_or(0);
  if (total <= 0) {
    return; // disabled (default)
  }
  int64_t bsz = RecGetRecordInt("proxy.config.net.io_uring.fixed_arena_block_size").value_or(1048576);
  if (bsz <= 0) {
    return;
  }
  _block_size = static_cast<unsigned>(bsz);
  _nblocks    = static_cast<unsigned>(total / _block_size);
  if (_nblocks == 0) {
    return;
  }
  _region_len = static_cast<size_t>(_nblocks) * _block_size;
  // Page-aligned, pre-faulted region; the io_uring registration pins it.
  void *p = mmap(nullptr, _region_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  if (p == MAP_FAILED) {
    _region     = nullptr;
    _region_len = 0;
    Warning("io_uring fixed arena: mmap(%zu) failed; disabled", _region_len);
    return;
  }
  _region = static_cast<char *>(p);
  _free_blocks.reserve(_nblocks);
  for (uint32_t i = _nblocks; i-- > 0;) {
    _free_blocks.push_back(i);
  }
  Note("io_uring fixed arena: %u blocks x %u B = %zu MB", _nblocks, _block_size, _region_len >> 20);
}

void
UringFixedBufArena::ensure_registered()
{
  if (_region == nullptr) {
    return;
  }
  // Prototype: register the single region (== buffer index 0) independently on each ring.
  // Production: register once, then IORING_REGISTER_CLONE_BUFFERS into the other rings.
  static thread_local bool registered = false;
  if (registered) {
    return;
  }
  registered = true;
  int rc     = IOUringContext::local_context()->register_fixed_buffers(_region, _region_len);
  if (rc < 0) {
    Warning("io_uring fixed arena: register_buffers failed (%d) on this ring", rc);
  }
}

RegisteredBufferData *
UringFixedBufArena::alloc(int64_t req_bytes)
{
  if (_region == nullptr || req_bytes <= 0 || req_bytes > _block_size) {
    return nullptr;
  }
  std::lock_guard<std::mutex> g(_m);
  if (_free_blocks.empty()) {
    return nullptr; // exhausted -> caller falls back to a non-registered buffer
  }
  uint32_t idx = _free_blocks.back();
  _free_blocks.pop_back();
  RegisteredBufferData *d = _free_desc;
  if (d != nullptr) {
    _free_desc = d->_flink;
    d->_flink  = nullptr;
  } else {
    d = new RegisteredBufferData();
  }
  d->_block_idx  = idx;
  d->_buf_index  = 0;
  d->_data       = _region + static_cast<size_t>(idx) * _block_size;
  d->_size_index = iobuffer_size_to_index(_block_size, MAX_BUFFER_SIZE_INDEX);
  d->_mem_type   = NO_ALLOC; // dealloc() (never reached, free() is overridden) must not free it
  return d;
}

void
UringFixedBufArena::release(uint32_t block_idx, RegisteredBufferData *desc)
{
  std::lock_guard<std::mutex> g(_m);
  _free_blocks.push_back(block_idx);
  desc->_flink = _free_desc;
  _free_desc   = desc;
}

void
RegisteredBufferData::free()
{
  uint32_t idx = _block_idx;
  _data        = nullptr;
  _size_index  = BUFFER_SIZE_NOT_ALLOCATED;
  _mem_type    = NO_ALLOC;
  _buf_index   = -1;
  UringFixedBufArena::instance().release(idx, this);
}

#endif // TS_USE_LINUX_IO_URING
