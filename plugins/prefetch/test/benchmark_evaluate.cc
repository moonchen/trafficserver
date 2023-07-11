/** @file

Simple benchmark for ProxyAllocator

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

#define CATCH_CONFIG_ENABLE_BENCHMARKING
#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "../common.h"
#include <charconv>

static uint32_t
to_uint32(StringView s)
{
  uint32_t value;
  std::from_chars_result result = std::from_chars(s.begin(), s.end(), value);
  if (result.ec == std::errc{}) {
    return value;
  } else if (result.ec == std::errc::result_out_of_range) {
    return std::numeric_limits<uint32_t>::max();
  } else {
    return 0;
  }
}

static uint32_t
to_uint32_stringstream(StringView s)
{
  String str{s};
  std::istringstream iss{str};
  uint32_t out;
  iss >> out;
  return out;
}

static uint64_t
to_uint64(StringView s)
{
  uint64_t value;
  std::from_chars_result result = std::from_chars(s.begin(), s.end(), value);
  if (result.ec == std::errc{}) {
    return value;
  } else if (result.ec == std::errc::result_out_of_range) {
    return std::numeric_limits<uint64_t>::max();
  } else {
    return 0;
  }
}

static uint32_t
to_uint64_stringstream(StringView s)
{
  String str{s};
  std::istringstream iss{str};
  uint64_t out;
  iss >> out;
  return out;
}

TEST_CASE("Evaluate", "[benchmark]")
{
  StringView sv{"123456"};
  BENCHMARK("to_uint32")
  {
    return to_uint32(sv);
  };
  BENCHMARK("to_uint32_stringstream")
  {
    return to_uint32_stringstream(sv);
  };
  BENCHMARK("to_uint64")
  {
    return to_uint64(sv);
  };
  BENCHMARK("to_uint64_stringstream")
  {
    return to_uint64_stringstream(sv);
  };
}
