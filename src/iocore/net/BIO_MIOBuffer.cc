/** @file
 *
 *  OpenSSL BIO that wraps a MIOBuffer
 *
 *  @section license License
 *
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "BIO_MIOBuffer.h"
#include "tscore/Diags.h"
#include "tsutil/DbgCtl.h"

DbgCtl dbg_ctl_bio_miobuffer{"ssl_bio_miobuffer"};

struct BIO_MIOBuffer_Context {
  MIOBuffer      *buffer{nullptr};
  IOBufferReader *reader{nullptr};
};

// Create a new BIO with a null MIOBuffer
static int
miobuffer_create(BIO *bio)
{
  BIO_MIOBuffer_Context *ctx = new BIO_MIOBuffer_Context{};
  if (!ctx) {
    return 0; // Memory allocation failure
  }

  BIO_set_data(bio, ctx);
  BIO_set_init(bio, 0);
  return 1;
}

// Set the MIOBuffer for the BIO
int
miobuffer_set_buffer(BIO *bio, MIOBuffer *buffer)
{
  BIO_MIOBuffer_Context *ctx = static_cast<BIO_MIOBuffer_Context *>(BIO_get_data(bio));
  if (!ctx) {
    return 0; // Context not initialized
  }

  if (buffer == nullptr) {
    Error("miobuffer_set_buffer: null buffer");
    return 0;
  }

  ctx->buffer = buffer;
  ctx->reader = ctx->buffer->alloc_reader();
  BIO_set_init(bio, 1);
  BIO_set_retry_read(bio);
  BIO_set_retry_write(bio);

  return 1;
}

// Free the BIO and its associated MIOBuffer
static int
miobuffer_destroy(BIO *bio)
{
  if (!bio) {
    return 0;
  }
  BIO_MIOBuffer_Context *ctx = static_cast<BIO_MIOBuffer_Context *>(BIO_get_data(bio));
  if (ctx) {
    if (ctx->reader) {
      ctx->reader->dealloc();
    }
    // don't free the MIOBuffer.  It's not owned by this BIO.
    delete ctx;
    BIO_set_data(bio, nullptr);
  }
  BIO_set_init(bio, 0);
  return 1;
}

// Write data into MIOBuffer
/*
static int
miobuffer_write_ex(BIO *bio, const char *in, size_t inlen, size_t *written)
{
  BIO_MIOBuffer_Context *ctx = static_cast<BIO_MIOBuffer_Context *>(BIO_get_data(bio));

  if (inlen == 0) {
    *written = 0;
    return 1;
  }

  if (!ctx) {
    Error("miobuffer_write_ex: null context");
    return 0;
  }

  if (!ctx->buffer) {
    Error("miobuffer_write_ex: null buffer");
    return 0;
  }

  if (!in) {
    Error("miobuffer_write_ex: null input");
    return 0;
  }

  int bytes_written = ctx->buffer->write(in, inlen);
  if (bytes_written > 0) {
    *written = bytes_written;
    return 1;
  } else {
    *written = 0;
    return 0;
  }
}
  */
static int
miobuffer_write_ex(BIO *bio, const char *in, size_t inlen, size_t *written)
{
  BIO_MIOBuffer_Context *ctx = static_cast<BIO_MIOBuffer_Context *>(BIO_get_data(bio));
  BIO_clear_retry_flags(bio);

  *written = 0;

  if (!ctx || !ctx->buffer) {
    Error("miobuffer_write_ex: BIO %p - null context or buffer", bio);
    return 0;
  }

  if (inlen > 0 && !in) {
    // OpenSSL should not call us with null input if inlen > 0
    Error("miobuffer_write_ex: BIO %p - null input buffer provided with inlen=%zu", bio, inlen);
    return 0;
  }

  if (inlen == 0) {
    Dbg(dbg_ctl_bio_miobuffer, "BIO=%p write_ex: Attempting write of 0 bytes (success)", bio);
    return 1;
  }

  Dbg(dbg_ctl_bio_miobuffer, "BIO=%p write_ex: Attempting write of %zu bytes", bio, inlen);

  int64_t bytes_written = ctx->buffer->write(in, inlen);
  // 5. Process the result
  if (bytes_written >= 0) {
    *written = bytes_written;
    Dbg(dbg_ctl_bio_miobuffer, "BIO=%p write_ex: Successfully wrote %zu bytes (requested %zu)", bio, *written, inlen);
    return 1;
  } else {
    Error("miobuffer_write_ex: BIO %p - buffer->write() returned error %" PRId64, bio, bytes_written);
    *written = 0;
    return 0;
  }
}

// Read data from MIOBuffer
/*
static int
miobuffer_read_ex(BIO *bio, char *out, size_t outlen, size_t *readbytes)
{
  BIO_MIOBuffer_Context *ctx = static_cast<BIO_MIOBuffer_Context *>(BIO_get_data(bio));

  if (!ctx) {
    Error("miobuffer_read_ex: null context");
    *readbytes = 0;
    return 0;
  }

  if (!ctx->reader) {
    Error("miobuffer_read_ex: null reader");
    *readbytes = 0;
    return 0;
  }

  if (!out) {
    Error("miobuffer_read_ex: null output buffer");
    *readbytes = 0;
    return 0;
  }

  if (outlen == 0) {
    Error("miobuffer_read_ex: output length is zero");
    *readbytes = 0;
    return 0;
  }

  int64_t avail = ctx->reader->read_avail();
  if (avail <= 0) {
    *readbytes = 0;
    return -1;
  }

  int64_t bytes_to_read = std::min<int64_t>(avail, outlen);
  int64_t bytes_copied  = ctx->reader->read(out, bytes_to_read);

  if (bytes_copied > 0) {
    *readbytes = bytes_copied;
    return 1;
  } else {
    *readbytes = 0;
    return 0;
  }
}
*/
static int
miobuffer_read_ex(BIO *bio, char *out, size_t outlen, size_t *readbytes)
{
  BIO_MIOBuffer_Context *ctx = static_cast<BIO_MIOBuffer_Context *>(BIO_get_data(bio));
  BIO_clear_retry_flags(bio);

  if (!ctx) {
    Error("miobuffer_read_ex: null context");
    *readbytes = 0;
    return 0;
  }

  if (!ctx->reader) {
    Error("miobuffer_read_ex: null reader");
    *readbytes = 0;
    return 0;
  }

  if (!out) {
    Error("miobuffer_read_ex: null output buffer");
    *readbytes = 0;
    return 0;
  }

  *readbytes = 0;

  int64_t avail = ctx->reader->read_avail();

  Dbg(dbg_ctl_bio_miobuffer, "BIO=%p read_ex: Attempting read, outlen=%zu, avail=%" PRId64, bio, outlen, avail);

  if (avail <= 0) {
    BIO_set_retry_read(bio); // Set the specific retry reason
    Dbg(dbg_ctl_bio_miobuffer, "BIO=%p read_ex: No data available, setting retry_read", bio);
    return 0;
  }

  int64_t bytes_to_read = std::min<int64_t>(avail, outlen);
  if (bytes_to_read <= 0) {
    // This might happen if outlen was 0. Nothing to do.
    Dbg(dbg_ctl_bio_miobuffer, "BIO=%p read_ex: bytes_to_read is 0 (outlen was likely 0)", bio);
    return 1;
  }

  int64_t bytes_copied = ctx->reader->read(out, bytes_to_read);
  if (bytes_copied > 0) {
    *readbytes = bytes_copied;
    Dbg(dbg_ctl_bio_miobuffer, "BIO=%p read_ex: Successfully read %zu bytes", bio, *readbytes);
    return 1;
  } else {
    Error("miobuffer_read_ex: BIO %p - reader->read() returned %" PRId64 " despite avail=%" PRId64 ", bytes_to_read=%" PRId64, bio,
          bytes_copied, avail, bytes_to_read);
    *readbytes = 0;
    return 0;
  }
}

// BIO control operations (flush, pending, etc.)
static long
miobuffer_ctrl(BIO *bio, int cmd, [[maybe_unused]] long num, [[maybe_unused]] void *ptr)
{
  BIO_MIOBuffer_Context *ctx = static_cast<BIO_MIOBuffer_Context *>(BIO_get_data(bio));
  long                   ret = 0;

  switch (cmd) {
  case BIO_CTRL_FLUSH:
    // Flush is a no-op for MIOBuffer
    ret = 1;
    break;
  case BIO_CTRL_PENDING:
    ret = ctx && ctx->reader ? ctx->reader->read_avail() : 0;
    break;
  case BIO_CTRL_EOF:
    // MIOBuffer has no EOF concept
    ret = 0;
    break;
  case BIO_CTRL_SET_CLOSE:
    // owning the underlying MIOBuffer is not supported
    ret = 0;
    break;
  case BIO_CTRL_GET_CLOSE:
    ret = 0;
    break;
  default:
    // output debug message about unknown ctrl command
    Dbg(dbg_ctl_bio_miobuffer, "Unknown BIO control command: %d", cmd);
    ret = 0;
    break;
  }
  return ret;
}

#ifndef HAVE_BIO_METH_NEW
static const BIO_METHOD miobuffer_methods[] = {
  {
   .type          = BIO_TYPE_SOURCE_SINK,
   .name          = "MIOBuffer",
   .bwrite        = miobuffer_write,
   .bread         = miobuffer_read,
   .bputs         = nullptr,
   .bgets         = nullptr,
   .ctrl          = miobuffer_ctrl,
   .create        = miobuffer_create,
   .destroy       = miobuffer_free,
   .callback_ctrl = nullptr,
   }
};
#else
static const BIO_METHOD *miobuffer_methods = [] {
  BIO_METHOD *methods = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "MIOBuffer");
  BIO_meth_set_write_ex(methods, miobuffer_write_ex);
  BIO_meth_set_read_ex(methods, miobuffer_read_ex);
  BIO_meth_set_ctrl(methods, miobuffer_ctrl);
  BIO_meth_set_create(methods, miobuffer_create);
  BIO_meth_set_destroy(methods, miobuffer_destroy);
  return methods;
}();
#endif

const BIO_METHOD *
BIO_s_miobuffer()
{
  return miobuffer_methods;
}
