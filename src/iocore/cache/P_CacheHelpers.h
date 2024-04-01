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

#include <sys/types.h>
#include "tscore/ink_align.h"

// TODO: split these out
constexpr size_t
ROUND_TO(size_t _x, size_t _y)
{
  return INK_ALIGN((_x), (_y));
}

constexpr off_t
DIR_BLOCK_SIZE(int _i)
{
  return (CACHE_BLOCK_SIZE << DIR_BLOCK_SHIFT(_i));
}

constexpr unsigned int
DIR_MASK_TAG(uint32_t _t)
{
  return ((_t) & ((1 << DIR_TAG_WIDTH) - 1));
}

constexpr size_t
ROUND_TO_CACHE_BLOCK(size_t _x)
{
  return INK_ALIGN(_x, CACHE_BLOCK_SIZE);
}

#define DIR_SIZE_WITH_BLOCK(_i) ((1 << DIR_SIZE_WIDTH) * DIR_BLOCK_SIZE(_i))

constexpr inline uint32_t
round_to_approx_dir_size(uint32_t _s)
{
  return (_s <= DIR_SIZE_WITH_BLOCK(0) ?
            ROUND_TO(_s, DIR_BLOCK_SIZE(0)) :
            (_s <= DIR_SIZE_WITH_BLOCK(1) ?
               ROUND_TO(_s, DIR_BLOCK_SIZE(1)) :
               (_s <= DIR_SIZE_WITH_BLOCK(2) ? ROUND_TO(_s, DIR_BLOCK_SIZE(2)) : ROUND_TO(_s, DIR_BLOCK_SIZE(3)))));
}
