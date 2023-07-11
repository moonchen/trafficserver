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
#include <sstream>
#include <istream>
#include <iomanip>
#include <cstdint>
#include <cinttypes>

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
  String stmt;
  uint32_t len              = 0;
  StringView::size_type pos = v.find_first_of(':');
  if (StringView::npos != pos) {
    stmt.assign(v.substr(0, pos));
    std::istringstream iss(stmt);
    iss >> len;
    v = v.substr(pos + 1);
  }
  PrefetchDebug("statement: '%s', formatting length: %" PRIu32, stmt.c_str(), len);

  uint64_t result = 0;
  pos             = v.find_first_of("+-");

  if (String::npos == pos) {
    stmt.assign(v.substr(0, pos));
    std::istringstream iss(stmt);

    if (policy == EvalPolicy::Overflow64) {
      iss >> result;
    } else {
      uint32_t tmp32;
      iss >> tmp32;
      result = tmp32;
    }

    PrefetchDebug("Single-operand expression: %s -> %" PRIu64, stmt.c_str(), result);
  } else {
    const String leftOperand(v.substr(0, pos));
    std::istringstream liss(leftOperand);
    uint64_t a64 = 0;

    if (policy == EvalPolicy::Overflow64) {
      liss >> a64;
    } else {
      uint32_t a32;
      liss >> a32;
      a64 = a32;
    }
    PrefetchDebug("Left-operand expression: %s -> %" PRIu64, leftOperand.c_str(), a64);

    const String rightOperand(v.substr(pos + 1));
    std::istringstream riss(rightOperand);
    uint64_t b64 = 0;

    if (policy == EvalPolicy::Overflow64) {
      riss >> b64;
    } else {
      uint32_t b32;
      riss >> b32;
      b64 = b32;
    }

    PrefetchDebug("Right-operand expression: %s -> %" PRIu64, rightOperand.c_str(), b64);

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
  PrefetchDebug("evaluation of '%.*s' resulted in '%s'", (int)view.length(), view.data(), convert.str().c_str());
  return convert.str();
}
