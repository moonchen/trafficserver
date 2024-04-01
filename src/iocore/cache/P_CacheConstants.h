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

#include <cstdint>
#include <sys/types.h>

#include "iocore/cache/AggregateWriteBuffer.h"
#include "iocore/eventsystem/IOBuffer.h"
#include "P_CacheDoc.h"

// Dir
constexpr uint32_t LOOKASIDE_SIZE = 256;

constexpr uint8_t DIR_TAG_WIDTH = 12;
#define SIZEOF_DIR            10
#define ESTIMATED_OBJECT_SIZE 8000

#define MAX_DIR_SEGMENTS        (32 * (1 << 16))
#define DIR_DEPTH               4
#define MAX_ENTRIES_PER_SEGMENT (1 << 16)
#define MAX_BUCKETS_PER_SEGMENT (MAX_ENTRIES_PER_SEGMENT / DIR_DEPTH)
#define DIR_SIZE_WIDTH          6
#define DIR_BLOCK_SIZES         4
#define DIR_BLOCK_SHIFT(_i)     (3 * (_i))
#define DIR_OFFSET_BITS         40
#define DIR_OFFSET_MAX          ((((off_t)1) << DIR_OFFSET_BITS) - 1)

#define SYNC_MAX_WRITE (2 * 1024 * 1024)
#define SYNC_DELAY     HRTIME_MSECONDS(500)

// Vol
constexpr uint8_t CACHE_BLOCK_SHIFT = 9;
constexpr off_t CACHE_BLOCK_SIZE    = 1 << CACHE_BLOCK_SHIFT; // 512, smallest sector size

// Stripe
constexpr uint32_t STRIPE_MAGIC            = 0xF1D0F00D;
constexpr off_t START_BLOCKS               = 16; // 8k, STORE_BLOCK_SIZE
constexpr off_t START_POS                  = START_BLOCKS * CACHE_BLOCK_SIZE;
constexpr off_t EVACUATION_SIZE            = 2 * AGG_SIZE;      // 8MB
constexpr off_t STRIPE_BLOCK_SIZE          = 1024 * 1024 * 128; // 128MB
constexpr off_t MIN_STRIPE_SIZE            = STRIPE_BLOCK_SIZE;
constexpr off_t MAX_STRIPE_SIZE            = 512ll * 1024 * 1024 * 1024 * 1024; // 512TB
constexpr off_t MAX_FRAG_SIZE              = (AGG_SIZE - sizeof(Doc));          // true max
constexpr off_t LEAVE_FREE                 = DEFAULT_MAX_BUFFER_SIZE;
constexpr off_t PIN_SCAN_EVERY             = 16; // scan every 1/16 of disk
constexpr off_t STRIPE_HASH_TABLE_SIZE     = 32707;
constexpr unsigned short STRIPE_HASH_EMPTY = 0xFFFF;
constexpr off_t STRIPE_HASH_ALLOC_SIZE     = 8 * 1024 * 1024;       // one chance per this unit
constexpr off_t EVACUATION_BUCKET_SIZE     = (2 * EVACUATION_SIZE); // 16MB
constexpr off_t RECOVERY_SIZE              = EVACUATION_SIZE;       // 8MB
constexpr int AIO_AGG_WRITE_IN_PROGRESS    = -2;
constexpr int64_t AUTO_SIZE_RAM_CACHE      = -1;                    // 1-1 with directory size
constexpr int DEFAULT_TARGET_FRAGMENT_SIZE = 1048576 - sizeof(Doc); // 1MB

constexpr int AIO_NOT_IN_PROGRESS = -1;
