/** @file
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

#include "ts/ts.h"

#include <string_view>

struct Config;
struct HttpHeader;

// Marks the first block request of a client request that slice serves through its intercept.
constexpr std::string_view SLICE_FIRST_BLOCK_HEADER = {"Slice-First-Block"};

/** Reserve the transaction argument that marks slice's block requests for cache_promote and cache_range_requests,
  which reserve it under the same name.
 */
void reserve_slice_block_arg();

// Mark the transaction as a request for one of slice's blocks.
void mark_slice_block(TSHttpTxn txnp);

/** At READ_RESPONSE_HDR of a block request, before cache_range_requests sees the response.

  For a rule whose first block can be other than block 0: a 200 without Content-Range to a Range is the whole object.
  Its one complete copy goes under the key that Config::m_whole_copy names: block 0's (stored only by a request for
  block 0), the block's own, or block 0's by moving this request's cache write there. The object and that block are
  remembered, so that later requests ask for the block. A 206 means that upstream honors Range for the object again.
 */
void note_block_answer(TSHttpTxn txnp, Config *config);

/** At CACHE_LOOKUP_COMPLETE of a miss of the first block of a client request, with --whole-object-lookup: look for
  the object's complete copy under block 0's key, if the block is a later one. CACHE_LOOKUP_COMPLETE runs again if
  that lookup finds an object.

  @return whether the second lookup will run
 */
bool look_up_whole_copy(TSHttpTxn txnp, Config const *config);

/** For a block request, at remap: mark it, and watch the transaction if it is the first block of a client request
  that slice serves through its intercept.

  @param header the client request of the block transaction; the first block marker is removed from it
  @param contp a continuation that runs first_block_handler, with the Config as its data
 */
void watch_block_request(TSHttpTxn txnp, HttpHeader &header, TSCont contp);

int first_block_handler(TSCont contp, TSEvent event, void *edata);
