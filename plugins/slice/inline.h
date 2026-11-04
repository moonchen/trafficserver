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

struct Config;
struct HttpHeader;

/** Serve a GET in the client transaction, starting with the block that holds its first byte.

  The client request becomes the request for that block, so the rest of the remap chain
  (cache_range_requests in particular) keys, routes and stores it exactly like a block request.
  The decision waits for the response: a block that already is the client's response is sent as
  is, and otherwise the client gets its part of the block followed by the rest of the bytes it asked for.

  @return true if the transaction now takes the inline path; the remap chain must continue.
 */
bool inline_first_block(TSHttpTxn txnp, Config *config, HttpHeader &header);
