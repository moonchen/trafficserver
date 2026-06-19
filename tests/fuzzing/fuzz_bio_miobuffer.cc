/** @file

   fuzzing iocore/net BIO_MIOBuffer -- the in-memory MIOBuffer BIO used by the
   layered TLS VConnection as SSL's read/write BIO.

   @section license License

   Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements.
   See the NOTICE file distributed with this work for additional information regarding copyright
   ownership.  The ASF licenses this file to you under the Apache License, Version 2.0 (the
   "License"); you may not use this file except in compliance with the License.  You may obtain a
   copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software distributed under the License
   is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
   or implied. See the License for the specific language governing permissions and limitations under
   the License.
*/

#include "BIO_MIOBuffer.h"
#include "iocore/eventsystem/IOBuffer.h"
#include "iocore/eventsystem/EventSystem.h"
#include "records/RecordsConfig.h"
#include "tscore/BaseLogFile.h"
#include "tscore/Diags.h"
#include "tscore/Layout.h"

#include <openssl/bio.h>

#include <algorithm>
#include <vector>

namespace
{
bool g_inited = false;

// new_MIOBuffer allocates from the calling thread's ProxyAllocator, so the fuzz
// thread needs a thread-specific EThread (mirrors the libinknet unit-test main).
void
fuzzer_init()
{
  Layout::create();
  DiagsPtr::set(new Diags("fuzzing", "", "", new BaseLogFile("stderr")));
  RecProcessInit();
  LibRecordsConfigInit();
  ink_event_system_init(EVENT_SYSTEM_MODULE_PUBLIC_VERSION);
  eventProcessor.start(1);
  (new EThread)->set_specific();
}
} // namespace

// Drive a sequence of write/read/ctrl/consume operations -- with adversarial
// sizes and interleavings derived from the fuzz input -- through the MIOBuffer
// BIO, looking for crashes, asserts, or memory errors (under ASan).
extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *input_data, size_t size_data)
{
  if (!g_inited) {
    fuzzer_init();
    g_inited = true;
  }

  BIO *bio = BIO_new(BIO_s_miobuffer());
  if (bio == nullptr) {
    return 0;
  }
  MIOBuffer      *buffer = new_MIOBuffer(BUFFER_SIZE_INDEX_32K);
  IOBufferReader *reader = buffer->alloc_reader();
  if (miobuffer_set_buffer(bio, buffer, reader) != 1) {
    BIO_free(bio);
    free_MIOBuffer(buffer);
    return 0;
  }

  // Each step is (op, len, [bytes...]); op selects a BIO operation and len is an
  // adversarial length byte (0..255).
  size_t pos = 0;
  while (pos + 2 <= size_data) {
    uint8_t op  = input_data[pos++];
    size_t  len = input_data[pos++];
    switch (op % 5) {
    case 0: { // write up to len bytes from the remaining input
      size_t n = std::min(len, size_data - pos);
      BIO_write(bio, input_data + pos, static_cast<int>(n));
      pos += n;
      break;
    }
    case 1: { // read up to len bytes
      std::vector<char> out(len + 1);
      BIO_read(bio, out.data(), static_cast<int>(len));
      break;
    }
    case 2: // pending / has-data queries
      BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nullptr);
      (void)miobuffer_has_read_avail(bio);
      break;
    case 3: // flush
      BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, nullptr);
      break;
    case 4: { // consume, bounded to what is actually pending (the production contract)
      long pending = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nullptr);
      if (pending > 0) {
        miobuffer_consume(bio, std::min<int64_t>(len, pending));
      }
      break;
    }
    }
  }

  BIO_free(bio);
  free_MIOBuffer(buffer);
  return 0;
}
