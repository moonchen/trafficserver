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

#include <string>
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

/** The URL's own key: the key that the block request would have without slice and cache_range_requests, where the
  complete copy of an object whose upstream ignores Range is stored.

  It is the block's cache key without the block's Range. cache_range_requests keys a block as <URL>-<the block's
  Range>, and cachekey with --include-headers=Range keys it with a "Range:<the block's Range>" element, which is
  removed with the separator before it.

  @param[out] key the URL's own key
  @param[out] blockbeg the first byte of the block whose key the transaction has
  @return false if the transaction's cache key does not hold a block's Range
 */
bool url_key_of_block(TSHttpTxn txnp, Config const *config, std::string &key, int64_t &blockbeg);

/** At CACHE_LOOKUP_COMPLETE of a block request that missed: look up the URL's own key once more.
  CACHE_LOOKUP_COMPLETE runs again if that lookup finds an object.

  @param[out] blockbeg the first byte of the block
  @return whether the second lookup will run
 */
bool look_up_url_key(TSHttpTxn txnp, Config const *config, int64_t &blockbeg);

/** At READ_RESPONSE_HDR of a block request, before cache_range_requests sees the response: a 200 without
  Content-Range to a Range is the whole object, so its cache write moves to the URL's own key.
 */
void note_block_answer(TSHttpTxn txnp, Config const *config);

/** For a block request, at remap: mark it, and watch its cache lookup.

  @param header the client request of the block transaction; the first block marker is removed from it
  @param contp a continuation that runs block_handler, with the Config as its data
 */
void watch_block_request(TSHttpTxn txnp, HttpHeader &header, TSCont contp);

int block_handler(TSCont contp, TSEvent event, void *edata);
