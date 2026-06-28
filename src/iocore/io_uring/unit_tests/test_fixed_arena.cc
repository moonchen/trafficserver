/** @file

  Catch based unit tests for the io_uring registered-buffer arena's size classes.

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

#include <catch2/catch_test_macros.hpp>

#include "iocore/io_uring/UringFixedBufArena.h"

#include <atomic>
#include <cstdint>
#include <set>
#include <thread>
#include <vector>

// These tests drive the allocator core through the test-only constructor, which builds the
// size-class table + backing region from explicit parameters and skips records, io_uring
// registration, and metrics. The arena partitions ONE registered region (buffer index 0) into
// power-of-two size classes following the ATS IOBuffer size-index scheme; a class id is the
// IOBuffer size index, so a block's backing capacity is 128 << _size_index.

namespace
{
constexpr int64_t KiB = 1024;
constexpr int64_t MiB = 1024 * 1024;

int64_t
block_capacity(RegisteredBufferData *d)
{
  return int64_t{128} << d->_size_index;
}

// Index of the class whose block size is exactly `bsz`, or num_classes() if absent.
size_t
class_of(const UringFixedBufArena &a, int64_t bsz)
{
  for (size_t i = 0; i < a.num_classes(); ++i) {
    if (a.class_block_size(i) == static_cast<unsigned>(bsz)) {
      return i;
    }
  }
  return a.num_classes();
}
} // namespace

TEST_CASE("a disabled arena (zero total) hands out nothing", "[arena]")
{
  UringFixedBufArena a(0, 2 * MiB);
  REQUIRE_FALSE(a.enabled());
  REQUIRE(a.alloc(64 * KiB) == nullptr);
}

TEST_CASE("alloc picks the smallest size class that fits the request", "[arena]")
{
  UringFixedBufArena a(64 * MiB, 2 * MiB); // classes 64K..2M
  REQUIRE(a.enabled());

  struct Case {
    int64_t req;
    int64_t want;
  };
  const Case cases[] = {
    {64 * KiB,     64 * KiB }, // exact
    {64 * KiB + 1, 128 * KiB}, // one over rounds up to the next class
    {128 * KiB,    128 * KiB},
    {200 * KiB,    256 * KiB},
    {1 * MiB,      1 * MiB  },
    {1 * MiB + 1,  2 * MiB  }, // a nominal-1MiB Doc with overhead needs the 2M class
    {2 * MiB,      2 * MiB  }, // exact top class
  };

  for (const auto &c : cases) {
    RegisteredBufferData *d = a.alloc(c.req);
    REQUIRE(d != nullptr);
    CHECK(block_capacity(d) == c.want);
    CHECK(d->registered_index() == 0); // every block lives in the single registered region
    CHECK(d->data() >= a.region_base());
    CHECK(d->data() + c.want <= a.region_base() + a.region_len());
    d->free();
  }
}

TEST_CASE("a request larger than the top class falls through (counted oversize)", "[arena]")
{
  UringFixedBufArena a(64 * MiB, 1 * MiB); // top class = 1M
  REQUIRE(a.alloc(1 * MiB + 1) == nullptr);
  CHECK(a.oversize_count() == 1);
}

TEST_CASE("a 1 MiB object's Doc engages the arena under the default 2M top class", "[arena]")
{
  // The headline bug T3.3 fixes: with a 1 MiB top class a 1 MiB body + Doc overhead exceeds
  // the block and silently declines; the 2 MiB top class captures it.
  UringFixedBufArena    a(64 * MiB, 2 * MiB);
  RegisteredBufferData *d = a.alloc(1 * MiB + 4 * KiB);
  REQUIRE(d != nullptr);
  CHECK(block_capacity(d) == 2 * MiB);
  CHECK(a.oversize_count() == 0);
  d->free();
}

TEST_CASE("a class hands out distinct in-region blocks then reports exhaustion", "[arena]")
{
  // Even-bytes split across 6 classes (64K..2M): each class gets total/6 bytes, so the 2M
  // class holds (36 MiB / 6) / 2 MiB = 3 blocks.
  UringFixedBufArena a(36 * MiB, 2 * MiB);

  std::vector<RegisteredBufferData *> held;
  std::set<char *>                    bases;
  for (;;) {
    RegisteredBufferData *d = a.alloc(2 * MiB);
    if (d == nullptr) {
      break;
    }
    CHECK(bases.insert(d->data()).second);                          // distinct backing
    CHECK(d->data() >= a.region_base());                            // within the region
    CHECK(d->data() + 2 * MiB <= a.region_base() + a.region_len()); //
    held.push_back(d);
  }
  CHECK(held.size() == 3);
  CHECK(a.exhausted_count() == 1); // the one alloc that found the class empty

  // Recycling a block makes it allocatable again.
  held.back()->free();
  held.pop_back();
  RegisteredBufferData *again = a.alloc(2 * MiB);
  REQUIRE(again != nullptr);
  again->free();
  for (RegisteredBufferData *d : held) {
    d->free();
  }
}

TEST_CASE("an under-sized arena starves the large classes", "[arena]")
{
  // total < nclasses * top_block_size: the even-bytes split floors the big classes to 0 blocks.
  // They still exist but decline every request (-> heap), counted as exhausted (build() warns).
  UringFixedBufArena a(2 * MiB, 2 * MiB); // 6 classes, per_class ~349 KiB < 512K
  REQUIRE(a.enabled());

  const size_t big = class_of(a, 2 * MiB);
  REQUIRE(big < a.num_classes());

  // A 2 MiB request reaches the empty top class -> declines as exhausted, not oversize.
  CHECK(a.alloc(2 * MiB) == nullptr);
  CHECK(a.exhausted_count() == 1);
  CHECK(a.oversize_count() == 0);

  // The small classes (which did get blocks) still serve.
  RegisteredBufferData *d = a.alloc(64 * KiB);
  REQUIRE(d != nullptr);
  d->free();
}

TEST_CASE("in-use accounting follows alloc and free within a class", "[arena]")
{
  UringFixedBufArena a(64 * MiB, 2 * MiB);
  const size_t       cls = class_of(a, 256 * KiB);
  REQUIRE(cls < a.num_classes());

  RegisteredBufferData *d1 = a.alloc(256 * KiB);
  RegisteredBufferData *d2 = a.alloc(256 * KiB);
  CHECK(a.class_in_use(cls) == 2);
  CHECK(a.class_alloc(cls) == 2);

  d1->free();
  CHECK(a.class_in_use(cls) == 1);
  d2->free();
  CHECK(a.class_in_use(cls) == 0);
  CHECK(a.class_alloc(cls) == 2); // alloc count is monotonic; free does not decrement it
}

TEST_CASE("concurrent alloc/free is race-free and conserves the block pool", "[arena][concurrency]")
{
  UringFixedBufArena a(64 * MiB, 2 * MiB);

  // Hammer three distinct classes at once -- each thread rotates through the sizes, so all three
  // lock-free lists see concurrent pop/push (the single shared _flink offset is exercised on each).
  const int64_t sizes[] = {64 * KiB, 256 * KiB, 1 * MiB};
  constexpr int NSIZE   = 3;
  for (int64_t sz : sizes) {
    REQUIRE(class_of(a, sz) < a.num_classes());
    REQUIRE(a.class_nblocks(class_of(a, sz)) > NSIZE); // room for contention without constant exhaustion
  }

  constexpr int     NTHREAD = 8;
  constexpr int     ITERS   = 20000;
  std::atomic<bool> corrupt{false};
  std::atomic<int>  stamp{1};

  auto worker = [&](int tid) {
    for (int i = 0; i < ITERS; ++i) {
      RegisteredBufferData *d = a.alloc(sizes[(tid + i) % NSIZE]);
      if (d == nullptr) {
        continue; // transient exhaustion under contention is expected
      }
      // Stamp the block (sized by its actual class capacity) with a value no other thread uses; a
      // second concurrent holder of the same block would clobber a stamp and trip the re-read.
      const int     s     = stamp.fetch_add(1, std::memory_order_relaxed);
      volatile int *p     = reinterpret_cast<volatile int *>(d->data());
      const size_t  words = (size_t{128} << d->_size_index) / sizeof(int);
      p[0]                = s;
      p[words - 1]        = s;
      for (int k = 0; k < 64; ++k) {
        if (p[0] != s || p[words - 1] != s) {
          corrupt.store(true, std::memory_order_relaxed);
          break;
        }
      }
      d->free();
    }
  };

  std::vector<std::thread> threads;
  threads.reserve(NTHREAD);
  for (int t = 0; t < NTHREAD; ++t) {
    threads.emplace_back(worker, t);
  }
  for (std::thread &th : threads) {
    th.join();
  }

  CHECK_FALSE(corrupt.load()); // no two threads ever held the same block

  // Each hammered class is fully intact: in_use back to 0 and exactly nblocks distinct blocks are
  // reclaimable -- none lost into limbo, none duplicated.
  for (int64_t sz : sizes) {
    const size_t cls = class_of(a, sz);
    CHECK(a.class_in_use(cls) == 0);
    std::set<char *>                    seen;
    std::vector<RegisteredBufferData *> drained;
    for (RegisteredBufferData *d = a.alloc(sz); d != nullptr; d = a.alloc(sz)) {
      CHECK(seen.insert(d->data()).second);
      drained.push_back(d);
    }
    CHECK(drained.size() == a.class_nblocks(cls));
    for (RegisteredBufferData *d : drained) {
      d->free();
    }
  }
}
