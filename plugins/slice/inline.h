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

#include <cstdint>
#include <string_view>

struct Config;
struct HttpHeader;
struct Range;

/** Serve a GET in the client transaction, starting with the block that holds its first byte.

  The client request becomes the request for that block, so the rest of the remap chain
  (cache_range_requests in particular) keys, routes and stores it exactly like a block request.
  The decision waits for the response: a block that already is the client's response is sent as
  is, and otherwise the client gets its part of the block followed by the rest of the bytes it asked for.

  @return true if the transaction now takes the inline path; the remap chain must continue.
 */
bool inline_first_block(TSHttpTxn txnp, Config *config, HttpHeader &header);

/** Serve a range of a complete copy of the object (a cached 200 without Content-Range) that core cannot serve by
  itself, because another transaction is still writing the copy or the request is not HTTP/1.1. A transform cuts the
  range out of the copy as it arrives, and the response becomes a 206.

  @param want the range, which starts before @a total
  @param total the length of the copy
  @param range the Range header value of @a want
  @return false if the transform could not be added
 */
bool serve_window_from_copy(TSHttpTxn txnp, Config *config, Range const &want, int64_t total, std::string_view range);
