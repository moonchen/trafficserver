/** @file

  A brief file description

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

#include "P_CacheConstants.h"
#include "P_CacheDir.h"
#include "P_CacheStats.h"
#include "P_CacheStripe.h"

#include "iocore/eventsystem/EThread.h"

#include <atomic>

constexpr off_t STORE_BLOCKS_PER_STRIPE = STRIPE_BLOCK_SIZE / STORE_BLOCK_SIZE;

constexpr size_t
ROUND_TO_STORE_BLOCK(size_t _x)
{
  return INK_ALIGN((_x), STORE_BLOCK_SIZE);
}

// Documents

struct Cache;
class Stripe;
struct CacheDisk;
struct DiskStripe;
struct CacheVol;
class CacheEvacuateDocVC;

struct CacheVol {
  int vol_number            = -1;
  int scheme                = 0;
  off_t size                = 0;
  int num_vols              = 0;
  bool ramcache_enabled     = true;
  Stripe **stripes          = nullptr;
  DiskStripe **disk_stripes = nullptr;
  LINK(CacheVol, link);
  // per volume stats
  CacheStatsBlock vol_rsb;

  CacheVol() {}
};

// Global Data

extern Stripe **gstripes;
extern std::atomic<int> gnstripes;
extern ClassAllocator<OpenDirEntry> openDirEntryAllocator;
extern ClassAllocator<EvacuationBlock> evacuationBlockAllocator;
extern ClassAllocator<EvacuationKey> evacuationKeyAllocator;
extern unsigned short *vol_hash_table;

// inline Functions

inline constexpr off_t
dir_offset_evac_bucket(off_t _o)
{
  return _o / (EVACUATION_BUCKET_SIZE / CACHE_BLOCK_SIZE);
}

inline constexpr off_t
dir_evac_bucket(const Dir *_e)
{
  return dir_offset_evac_bucket(dir_offset(_e));
}

inline EvacuationBlock *
evacuation_block_exists(Dir const *dir, Stripe *stripe)
{
  auto bucket = dir_evac_bucket(dir);
  if (stripe->evac_bucket_valid(bucket)) {
    EvacuationBlock *b = stripe->evacuate[bucket].head;
    for (; b; b = b->link.next) {
      if (dir_offset(&b->dir) == dir_offset(dir)) {
        return b;
      }
    }
  }
  return nullptr;
}

inline EvacuationBlock *
new_EvacuationBlock(EThread *t)
{
  EvacuationBlock *b      = THREAD_ALLOC(evacuationBlockAllocator, t);
  b->init                 = 0;
  b->readers              = 0;
  b->earliest_evacuator   = nullptr;
  b->evac_frags.link.next = nullptr;
  return b;
}

inline void
free_EvacuationBlock(EvacuationBlock *b, EThread *t)
{
  EvacuationKey *e = b->evac_frags.link.next;
  while (e) {
    EvacuationKey *n = e->link.next;
    evacuationKeyAllocator.free(e);
    e = n;
  }
  THREAD_FREE(b, evacuationBlockAllocator, t);
}
