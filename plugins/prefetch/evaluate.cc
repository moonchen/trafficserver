/*
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

/**
 * @file evaluate.h
 * @brief Prefetch formula evaluation (header file).
 */

#include "evaluate.h"
#include <limits>
#include <sstream>
#include <istream>
#include <iomanip>
#include <cstdint>
#include <cinttypes>
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

/**
 * @brief Evaluate a math addition or subtraction expression.
 *
 * @param v string containing an expression, i.e. "3 + 4"
 * @return string containing the result, i.e. "7"
 */
String
evaluate(const StringView view, const EvalPolicy policy)
{
  if (view.empty()) {
    return String("");
  }

  StringView v = view;

  /* Find out if width is specified (hence leading zeros are required if the width is bigger then the result width) */
  StringView stmt;
  uint32_t len              = 0;
  StringView::size_type pos = v.find_first_of(':');
  if (StringView::npos != pos) {
    stmt = v.substr(0, pos);
    len  = to_uint32(stmt);
    v    = v.substr(pos + 1);
  }
  PrefetchDebug("statement: '%.*s', formatting length: %" PRIu32, static_cast<int>(stmt.length()), stmt.data(), len);

  uint64_t result = 0;
  pos             = v.find_first_of("+-");

  if (String::npos == pos) {
    // The whole statement is a number
    stmt = v.substr(0, pos);
    if (policy == EvalPolicy::Overflow64) {
      result = to_uint64(stmt);
    } else {
      result = to_uint32(stmt);
    }

    PrefetchDebug("Single-operand expression: %.*s -> %" PRIu64, static_cast<int>(stmt.length()), stmt.data(), result);
  } else {
    const StringView leftOperand(v.substr(0, pos));
    uint64_t a64 = 0;

    if (policy == EvalPolicy::Overflow64) {
      a64 = to_uint64(leftOperand);
    } else {
      a64 = to_uint32(leftOperand);
    }
    PrefetchDebug("Left-operand expression: %.*s -> %" PRIu64, static_cast<int>(leftOperand.length()), leftOperand.data(), a64);

    const StringView rightOperand(v.substr(pos + 1));
    uint64_t b64 = 0;

    if (policy == EvalPolicy::Overflow64) {
      b64 = to_uint64(rightOperand);
    } else {
      b64 = to_uint32(rightOperand);
    }

    PrefetchDebug("Right-operand expression: %.*s -> %" PRIu64, static_cast<int>(rightOperand.length()), rightOperand.data(), b64);

    if ('+' == v[pos]) {
      result = a64 + b64;
    } else {
      if (a64 <= b64) {
        result = 0;
      } else {
        result = a64 - b64;
      }
    }
  }

  std::ostringstream convert;
  convert << std::setw(len) << std::setfill('0') << result;
  const String &ret = convert.str();
  PrefetchDebug("evaluation of '%.*s' resulted in '%s'", static_cast<int>(view.length()), view.data(), ret.c_str());
  return ret;
}
