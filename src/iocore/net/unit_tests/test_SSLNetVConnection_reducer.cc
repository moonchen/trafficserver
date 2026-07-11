/** @file

  Catch based unit tests for SSLNetVConnection ("reducer")

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

#include "ssl_reducer_harness.h"

#include "../P_SSLConfig.h"
#include "iocore/eventsystem/EThread.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("reducer harness premises hold", "[SSLReducer]")
{
  REQUIRE(this_ethread() != nullptr);

  SSLConfig::scoped_config params;
  REQUIRE(params->client_ctx != nullptr); // outbound handshakes need this; must be non-null by default
}
