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

#include "inline.h"

#include "Config.h"
#include "HttpHeader.h"
#include "Range.h"
#include "Stage.h"
#include "first_block.h"
#include "prefetch.h"
#include "slice.h"

#include <algorithm>
#include <charconv>
#include <cinttypes>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

namespace
{
using namespace std::string_view_literals;

/** The part of the object the client asked for, as the half-open range [beg, end).

  A whole-object GET is [0, Range::maxval). The client gets [beg, min(end, total)) of an object of total bytes,
  nothing if beg is at or past the end.
 */
struct Window {
  int64_t beg{0};
  int64_t end{Range::maxval};
  bool    range{false}; // the client sent a Range

  bool
  satisfiable(int64_t const total) const
  {
    return beg < total;
  }

  int64_t
  hi(int64_t const total) const
  {
    return std::min(end, total);
  }

  // Whether the body of a served block [s, e) of the object is already exactly what the client gets.
  bool
  matches(int64_t const s, int64_t const e, int64_t const total) const
  {
    return satisfiable(total) && beg == s && hi(total) == e;
  }
};

struct InlineTxn {
  Config     *config{nullptr};
  std::string url; // effective URL, kept only when the size table exists
  Window      want;
  int64_t     block_beg{0}; // start of the first block, the one that holds want.beg
  std::string client_range; // the client's Range value, restored for logging
  bool        transform_added{false};
  bool        send_hook_added{false};
  bool        block_range{false}; // core serves the window from the cached block, by a Range within it
  int64_t     block_end{0};       // end of the cached block, with block_range
  int64_t     total{0};           // length of the object, with block_range or copy
  bool        copy{false};        // the transform cuts the window out of a complete copy of the object
  // Upstream got the client's own request, because the block would not be stored.
  bool pass_through{false};
  // The first block missed, and the URL's own key is looked up for a complete copy.
  bool relookup{false};
};

/** Response body producer for a transaction whose first block is not already the client's response.

  Core may serve a fresh or stale cached block, a new upstream response, or an error, and the plugin learns which
  only when the body starts. So the transform decides when it starts, from the header of the response it receives:
  for a block, it sends the client's window of it and continues past its end if the window does; for a window past
  the end of the object, or a 416 for an empty object, it produces nothing; anything else passes through unchanged.

  The part of the window after the first block comes from block requests, one per block, as slice sends them when it
  slices.
 */
struct Remainder {
  enum class Mode { Undecided, PassThrough, Window, Empty };

  TSHttpTxn   txnp{nullptr};
  Config     *config{nullptr};
  Window      want;
  int64_t     block_beg{0};   // start of the first block
  int64_t     copy_total{-1}; // length of the object, if the first block is a complete copy of it
  Mode        mode{Mode::Undecided};
  int64_t     first_end{0};  // end of the first block in the object
  int64_t     total{-1};     // length of the object
  int64_t     out_bytes{-1}; // bytes the client gets, or -1 if unknown
  int64_t     in_skip{0};    // first block bytes before the window
  int64_t     in_keep{0};    // end of the window within the first block's body
  int64_t     target{0};     // end of the window in the object
  std::string etag;
  std::string last_modified;
  std::string url; // pristine URL, the prefetch deduplication key as slice forms it
  bool        prefetchable{false};
  int64_t     prefetch_hwm{0}; // highest block scheduled for prefetch

  HdrMgr              request; // the remainder request without its Range, owned
  sockaddr_storage    client_ip{};
  TSIOBufferSizeIndex buffer_index{TS_IOBUFFER_SIZE_INDEX_32K};
  TSIOBufferWaterMark buffer_water_mark{TS_IOBUFFER_WATER_MARK_UNDEFINED};

  TSVIO            out_vio{nullptr};
  TSIOBuffer       out_buf{nullptr};
  TSIOBufferReader out_reader{nullptr};
  TSIOBuffer       ahead_buf{nullptr}; // remainder bytes that arrive before the first block has all arrived
  TSIOBufferReader ahead_reader{nullptr};
  int64_t          input_bytes{0};
  bool             input_done{false};

  int64_t      pos{0};       // next object byte the client needs
  int64_t      fetch_beg{0}; // object range of the current fetch
  int64_t      fetch_end{0};
  int64_t      skip{0};           // bytes at the start of the current fetch that the client already has
  bool         stop_early{false}; // the window ends in this block, which is not being stored
  Stage        upstream;
  TSHttpParser parser{nullptr};
  HdrMgr       response;
  bool         response_checked{false};
  bool         upstream_eos{false};
  bool         failed{false};

  ~Remainder()
  {
    if (nullptr != parser) {
      TSHttpParserDestroy(parser);
    }
    if (nullptr != out_reader) {
      TSIOBufferReaderFree(out_reader);
    }
    if (nullptr != out_buf) {
      TSIOBufferDestroy(out_buf);
    }
    if (nullptr != ahead_reader) {
      TSIOBufferReaderFree(ahead_reader);
    }
    if (nullptr != ahead_buf) {
      TSIOBufferDestroy(ahead_buf);
    }
  }
};

std::string_view
field_value(TSMBuffer buf, TSMLoc hdr, std::string_view name)
{
  TSMLoc const field = TSMimeHdrFieldFind(buf, hdr, name.data(), name.size());
  if (TS_NULL_MLOC == field) {
    return {};
  }
  int               len   = 0;
  char const *const value = TSMimeHdrFieldValueStringGet(buf, hdr, field, -1, &len);
  TSHandleMLocRelease(buf, hdr, field);
  return nullptr == value ? std::string_view{} : std::string_view{value, static_cast<size_t>(len)};
}

bool
parse_count(std::string_view &sv, int64_t &out)
{
  auto const [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), out);
  if (std::errc() != ec || out < 0) {
    return false;
  }
  sv.remove_prefix(ptr - sv.data());
  return true;
}

// "bytes <first>-<last>/<total>", returned as the half-open range [beg, end).
bool
parse_content_range(std::string_view sv, int64_t &beg, int64_t &end, int64_t &total)
{
  constexpr std::string_view prefix = "bytes "sv;
  int64_t                    last   = 0;

  if (!sv.starts_with(prefix)) {
    return false;
  }
  sv.remove_prefix(prefix.size());
  if (!parse_count(sv, beg) || !sv.starts_with('-')) {
    return false;
  }
  sv.remove_prefix(1);
  if (!parse_count(sv, last) || !sv.starts_with('/')) {
    return false;
  }
  sv.remove_prefix(1);
  if (!parse_count(sv, total) || !sv.empty()) {
    return false;
  }
  end = last + 1;
  return beg < end && end <= total;
}

// "bytes */<total>", the Content-Range of a 416.
bool
parse_unsatisfied_range(std::string_view sv, int64_t &total)
{
  constexpr std::string_view prefix = "bytes */"sv;

  if (!sv.starts_with(prefix)) {
    return false;
  }
  sv.remove_prefix(prefix.size());
  return parse_count(sv, total) && sv.empty();
}

void
fail_remainder(TSCont contp, Remainder *const rem, char const *const why)
{
  ERROR_LOG("Inline first block: %s", why);
  rem->failed = true;
  rem->upstream.abort();
  // Aborting the output makes core abort the client response instead of sending a short body.
  TSVConnAbort(TSTransformOutputVConnGet(contp), 1);
}

// Request the block that holds rem->pos, as request_block() does, so slice in the internal transaction passes it
// to cache_range_requests.
void
start_fetch(TSCont contp, Remainder *const rem)
{
  int64_t const blockbytes = rem->config->m_blockbytes;
  rem->fetch_beg           = rem->pos / blockbytes * blockbytes;
  rem->fetch_end           = std::min(rem->fetch_beg + blockbytes, rem->total);
  rem->skip                = rem->pos - rem->fetch_beg;

  // The Range asks for the whole block even at the end of the object: cache_range_requests keys a block by its Range.
  char rangestr[64];
  int  rangelen =
    snprintf(rangestr, sizeof(rangestr), "bytes=%" PRId64 "-%" PRId64, rem->fetch_beg, rem->fetch_beg + blockbytes - 1);
  Range rangecheck;
  if (rangelen <= 0 || static_cast<size_t>(rangelen) >= sizeof(rangestr) || !rangecheck.fromStringClosed(rangestr)) {
    fail_remainder(contp, rem, "could not form the block range");
    return;
  }
  HttpHeader req(rem->request.m_buffer, rem->request.m_lochdr);
  req.setKeyVal(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE, rangestr, rangelen);
  req.setKeyVal(rem->config->m_skip_header.data(), rem->config->m_skip_header.size(), "-", 1);
  // If the window ends inside this block, cache_range_requests reports whether it stores the block: the rest of a
  // block that is not being stored is not needed, and upstream is asked only for the window's part of it.
  char needstr[64];
  int  needlen = sizeof(needstr);
  if (rem->target < rem->fetch_end && Range(rem->fetch_beg, rem->target).toStringClosed(needstr, &needlen)) {
    req.setKeyVal(SLICE_CRR_HEADER.data(), SLICE_CRR_HEADER.size(), "1", 1);
    req.setKeyVal(SLICE_UNSTORED_HEADER.data(), SLICE_UNSTORED_HEADER.size(), needstr, needlen);
  } else {
    req.removeKey(SLICE_CRR_HEADER.data(), SLICE_CRR_HEADER.size());
    req.removeKey(SLICE_UNSTORED_HEADER.data(), SLICE_UNSTORED_HEADER.size());
  }
  std::string_view const ident = rem->config->m_crr_ident_header;
  if (!ident.empty()) {
    std::string const value = !rem->etag.empty()          ? std::string(TS_MIME_FIELD_ETAG) + " " + rem->etag :
                              !rem->last_modified.empty() ? std::string(TS_MIME_FIELD_LAST_MODIFIED) + " " + rem->last_modified :
                                                            std::string();
    if (!value.empty()) {
      req.setKeyVal(ident.data(), ident.size(), value.data(), value.size());
    }
  }

  TSHttpConnectOptions options = TSHttpConnectOptionsGet(TS_CONNECT_PLUGIN);
  options.addr                 = reinterpret_cast<sockaddr *>(&rem->client_ip);
  options.tag                  = PLUGIN_NAME;
  options.id                   = 0;
  options.buffer_index         = rem->buffer_index;
  options.buffer_water_mark    = rem->buffer_water_mark;

  TSVConn const vc = TSHttpConnectPlugin(&options);
  if (nullptr == vc) {
    fail_remainder(contp, rem, "could not connect for the remainder");
    return;
  }

  rem->upstream.setupConnection(vc);
  rem->upstream.setupVioWrite(contp, TSHttpHdrLengthGet(rem->request.m_buffer, rem->request.m_lochdr));
  TSHttpHdrPrint(rem->request.m_buffer, rem->request.m_lochdr, rem->upstream.m_write.m_iobuf);
  TSVIOReenable(rem->upstream.m_write.m_vio);
  rem->upstream.setupVioRead(contp, INT64_MAX);

  // Like slice, keep up to --prefetch-count blocks ahead of the block in flight. The request for this block
  // started before the first block finished, so the window starts after it.
  if (rem->prefetchable) {
    int64_t const     block = rem->fetch_beg / blockbytes;
    int64_t const     last  = std::min(block + rem->config->m_prefetchcount, (rem->target - 1) / blockbytes);
    BlockSource const source{rem->config, req, &rem->client_ip, rem->buffer_index, rem->buffer_water_mark};
    for (int64_t i = std::max(block + 1, rem->prefetch_hwm + 1); i <= last; ++i) {
      BgBlockFetch::schedule(source, static_cast<int>(i), rem->url);
    }
    rem->prefetch_hwm = std::max(rem->prefetch_hwm, last);
  }

  if (nullptr == rem->parser) {
    rem->parser = TSHttpParserCreate();
  } else {
    TSHttpParserClear(rem->parser);
  }
  rem->response.resetHeader();
  rem->response_checked = false;
  rem->upstream_eos     = false;
  rem->stop_early       = false;
}

enum class BlockCheck { Match, Unusable, NewVersion };

// Each block must come from the same representation as the first block.
BlockCheck
check_block(Remainder *const rem)
{
  HttpHeader const resp(rem->response.m_buffer, rem->response.m_lochdr);
  if (TS_HTTP_STATUS_PARTIAL_CONTENT != resp.status()) {
    DEBUG_LOG("Block status %d", resp.status());
    return BlockCheck::Unusable;
  }

  int64_t beg = 0, end = 0, total = 0;
  if (!parse_content_range(field_value(rem->response.m_buffer, rem->response.m_lochdr, TS_MIME_FIELD_CONTENT_RANGE), beg, end,
                           total) ||
      beg != rem->fetch_beg) {
    DEBUG_LOG("Block content range does not continue the first block");
    return BlockCheck::Unusable;
  }
  // A block that is not being stored ends with the window (start_fetch).
  bool const narrowed =
    rem->target < rem->fetch_end && end == rem->target && !resp.hasKey(SLICE_CRR_HEADER.data(), SLICE_CRR_HEADER.size());
  if (end != std::min(rem->fetch_end, total) && !narrowed) {
    DEBUG_LOG("Block content range does not cover the block");
    return BlockCheck::Unusable;
  }

  bool same = total == rem->total;
  if (same && !rem->etag.empty()) {
    same = field_value(rem->response.m_buffer, rem->response.m_lochdr, TS_MIME_FIELD_ETAG) == rem->etag;
  } else if (same && !rem->last_modified.empty()) {
    same = field_value(rem->response.m_buffer, rem->response.m_lochdr, TS_MIME_FIELD_LAST_MODIFIED) == rem->last_modified;
  }
  return same ? BlockCheck::Match : BlockCheck::NewVersion;
}

/** The first block is older than this one. As slice does, request block 0 again with the new block's identity, so
  cache_range_requests (with --consider-ident) replaces the stored first block for the next request.
 */
void
repair_first_block(Remainder *const rem)
{
  std::string_view const ident = rem->config->m_crr_ident_header;
  if (ident.empty()) {
    return;
  }
  std::string_view const etag  = field_value(rem->response.m_buffer, rem->response.m_lochdr, TS_MIME_FIELD_ETAG);
  std::string_view const lm    = field_value(rem->response.m_buffer, rem->response.m_lochdr, TS_MIME_FIELD_LAST_MODIFIED);
  std::string const      value = !etag.empty() ? std::string(TS_MIME_FIELD_ETAG) + " " + std::string(etag) :
                                 !lm.empty()   ? std::string(TS_MIME_FIELD_LAST_MODIFIED) + " " + std::string(lm) :
                                                 std::string();
  if (value.empty()) {
    return;
  }
  HttpHeader req(rem->request.m_buffer, rem->request.m_lochdr);
  req.setKeyVal(ident.data(), ident.size(), value.data(), value.size());
  DEBUG_LOG("Refetching the first block for a new version: %s", value.c_str());
  BgBlockFetch::schedule(BlockSource{rem->config, req, &rem->client_ip, rem->buffer_index, rem->buffer_water_mark}, 0, rem->url);
}

/** Choose the mode from the response the transform receives, which is the one core serves.

  Core copies that response (cached or upstream) for the transform; cache_range_requests has already turned a
  stored or upstream 206 into a 200 that keeps its Content-Range.
 */
void
choose_mode(TSCont contp, Remainder *const rem)
{
  TSVIO const   in_vio   = TSVConnWriteVIOGet(contp);
  int64_t const in_bytes = TSVIONBytesGet(in_vio);

  TxnHdrMgr resp;
  if (!resp.populateFrom(rem->txnp, TSHttpTxnTransformRespGet)) {
    rem->mode = Remainder::Mode::PassThrough;
    return;
  }
  TSHttpStatus const status = TSHttpHdrStatusGet(resp.m_buffer, resp.m_lochdr);
  std::string_view   cr     = field_value(resp.m_buffer, resp.m_lochdr, TS_MIME_FIELD_CONTENT_RANGE);
  int64_t            s = 0, e = 0, total = 0;
  bool               block = false;

  if (0 <= rem->copy_total) {
    // A complete copy holds the object from byte 0. While another transaction still writes it, core does not know its
    // length yet.
    block = TS_HTTP_STATUS_OK == status && cr.empty() && (in_bytes == rem->copy_total || INT64_MAX == in_bytes);
    e     = rem->copy_total;
    total = rem->copy_total;
  } else {
    block = (TS_HTTP_STATUS_OK == status || TS_HTTP_STATUS_PARTIAL_CONTENT == status) && parse_content_range(cr, s, e, total) &&
            s == rem->block_beg && in_bytes == e - s;
  }
  if (block) {
    rem->total = total;
    if (!rem->want.satisfiable(total)) {
      // The send hook answers with a 416.
      rem->mode      = Remainder::Mode::Empty;
      rem->out_bytes = 0;
    } else {
      int lookup = TS_CACHE_LOOKUP_MISS;
      TSHttpTxnCacheLookupStatusGet(rem->txnp, &lookup);
      // Slice prefetches when the first block missed or was stale; cache_range_requests reports that to it.
      rem->prefetchable = 0 < rem->config->m_prefetchcount && TS_CACHE_LOOKUP_HIT_FRESH != lookup;
      rem->mode         = Remainder::Mode::Window;
      rem->first_end    = e;
      rem->pos          = e;
      rem->target       = rem->want.hi(total);
      rem->in_skip      = rem->want.beg - s;
      rem->in_keep      = std::min(rem->target, e) - s;
      rem->out_bytes    = rem->target - rem->want.beg;
      rem->etag.assign(field_value(resp.m_buffer, resp.m_lochdr, TS_MIME_FIELD_ETAG));
      rem->last_modified.assign(field_value(resp.m_buffer, resp.m_lochdr, TS_MIME_FIELD_LAST_MODIFIED));
    }
  } else if (TS_HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE == status && !rem->want.range && parse_unsatisfied_range(cr, total) &&
             0 == total) {
    rem->mode      = Remainder::Mode::Empty;
    rem->out_bytes = 0;
  } else {
    rem->mode      = Remainder::Mode::PassThrough;
    rem->out_bytes = INT64_MAX == in_bytes ? -1 : in_bytes;
  }
  DEBUG_LOG("Inline first block transform: mode %d, out %" PRId64, static_cast<int>(rem->mode), rem->out_bytes);
}

void
pump_remainder(TSCont contp, Remainder *const rem)
{
  if (rem->failed) {
    return;
  }

  bool produced = false;

  if (Remainder::Mode::Undecided == rem->mode) {
    choose_mode(contp, rem);
    rem->out_buf    = TSIOBufferCreate();
    rem->out_reader = TSIOBufferReaderAlloc(rem->out_buf);
    // The write size becomes the client's Content-Length; an unknown length is written as INT64_MAX.
    rem->out_vio =
      TSVConnWrite(TSTransformOutputVConnGet(contp), contp, rem->out_reader, rem->out_bytes < 0 ? INT64_MAX : rem->out_bytes);
  }

  if (!rem->input_done) {
    TSVIO const in_vio = TSVConnWriteVIOGet(contp);
    if (nullptr == TSVIOBufferGet(in_vio)) {
      rem->input_done = true;
    } else {
      int64_t const todo = TSVIONTodoGet(in_vio);
      int64_t       n    = 0;
      if (0 < todo) {
        TSIOBufferReader const in_reader = TSVIOReaderGet(in_vio);
        n                                = std::min(todo, TSIOBufferReaderAvail(in_reader));
        if (0 < n) {
          // Copy the part of these input bytes that lies in [keep_beg, keep_end) of the input.
          int64_t keep_beg = 0, keep_end = INT64_MAX;
          if (Remainder::Mode::Window == rem->mode) {
            keep_beg = rem->in_skip;
            keep_end = rem->in_keep;
          } else if (Remainder::Mode::Empty == rem->mode) {
            keep_end = 0;
          }
          int64_t const copy_beg = std::max(rem->input_bytes, keep_beg);
          int64_t const copy_end = std::min(rem->input_bytes + n, keep_end);
          if (copy_beg < copy_end) {
            TSIOBufferCopy(rem->out_buf, in_reader, copy_end - copy_beg, copy_beg - rem->input_bytes);
            produced = true;
          }
          TSIOBufferReaderConsume(in_reader, n);
          TSVIONDoneSet(in_vio, TSVIONDoneGet(in_vio) + n);
          rem->input_bytes += n;
        }
      }
      if (0 < TSVIONTodoGet(in_vio)) {
        if (0 < n) {
          TSContCall(TSVIOContGet(in_vio), TS_EVENT_VCONN_WRITE_READY, in_vio);
        }
      } else {
        rem->input_done = true;
        TSContCall(TSVIOContGet(in_vio), TS_EVENT_VCONN_WRITE_COMPLETE, in_vio);
      }
    }
    if (rem->input_done) {
      if (Remainder::Mode::Window == rem->mode && rem->input_bytes != rem->first_end - rem->block_beg) {
        fail_remainder(contp, rem, "first block body length does not match its Content-Range");
        return;
      }
      if (Remainder::Mode::PassThrough == rem->mode && rem->out_bytes < 0) {
        // The length is known now; this completes the output.
        TSVIONBytesSet(rem->out_vio, rem->input_bytes);
        produced = true;
      }
      if (nullptr != rem->ahead_reader) {
        int64_t const n = TSIOBufferReaderAvail(rem->ahead_reader);
        if (0 < n) {
          TSIOBufferCopy(rem->out_buf, rem->ahead_reader, n, 0);
          TSIOBufferReaderConsume(rem->ahead_reader, n);
          produced = true;
        }
      }
    }
  }

  if (Remainder::Mode::Window == rem->mode && rem->response_checked) {
    TSIOBufferReader const reader  = rem->upstream.m_read.m_reader;
    int64_t                avail   = TSIOBufferReaderAvail(reader);
    int64_t                visited = 0;
    if (0 < rem->skip && 0 < avail) {
      int64_t const n = std::min(rem->skip, avail);
      TSIOBufferReaderConsume(reader, n);
      rem->skip -= n;
      avail     -= n;
      visited   += n;
    }
    int64_t const n = std::min(std::min(rem->fetch_end, rem->target) - rem->pos, avail);
    if (0 < n) {
      if (rem->input_done) {
        TSIOBufferCopy(rem->out_buf, reader, n, 0);
        produced = true;
      } else {
        if (nullptr == rem->ahead_buf) {
          rem->ahead_buf    = TSIOBufferCreate();
          rem->ahead_reader = TSIOBufferReaderAlloc(rem->ahead_buf);
        }
        TSIOBufferCopy(rem->ahead_buf, reader, n, 0);
      }
      TSIOBufferReaderConsume(reader, n);
      rem->pos += n;
      visited  += n;
      avail    -= n;
    }
    // Past the end of the window, the rest of a block that is being stored is read and dropped, as slice does, so
    // that it is still stored whole.
    bool const window_done = rem->pos >= rem->target;
    if (window_done && !rem->stop_early && 0 < avail) {
      int64_t const drop = std::min(rem->fetch_end - rem->pos, avail);
      TSIOBufferReaderConsume(reader, drop);
      rem->pos += drop;
      visited  += drop;
    }
    if (0 < visited) {
      TSVIONDoneSet(rem->upstream.m_read.m_vio, TSVIONDoneGet(rem->upstream.m_read.m_vio) + visited);
    }
    if (rem->pos == rem->fetch_end || (window_done && rem->stop_early)) {
      rem->upstream.close();
      rem->response_checked = false;
    } else if (rem->upstream_eos && 0 == TSIOBufferReaderAvail(reader)) {
      fail_remainder(contp, rem, "remainder ended early");
      return;
    } else if (0 < visited) {
      TSVIOReenable(rem->upstream.m_read.m_vio);
    }
  }

  // As slice does, a block is read as fast as it arrives, so that its cache write never waits for the client, and
  // the next block is requested only while at most one block waits for the client. The first remainder block is
  // requested as soon as the first block starts, and read while the first block still arrives.
  if (Remainder::Mode::Window == rem->mode && nullptr == rem->upstream.m_vc && rem->pos < rem->target) {
    int64_t const buffered =
      TSIOBufferReaderAvail(rem->out_reader) + (nullptr == rem->ahead_reader ? 0 : TSIOBufferReaderAvail(rem->ahead_reader));

    if (buffered <= rem->config->m_blockbytes) {
      start_fetch(contp, rem);
      if (rem->failed) {
        return;
      }
    }
  }

  if (produced) {
    TSVIOReenable(rem->out_vio);
  }
}

void
on_remainder_read(TSCont contp, Remainder *const rem, TSEvent const event)
{
  switch (event) {
  case TS_EVENT_VCONN_READ_READY:
  case TS_EVENT_VCONN_READ_COMPLETE:
    break;
  case TS_EVENT_VCONN_EOS:
    rem->upstream_eos = true;
    break;
  default:
    fail_remainder(contp, rem, "remainder connection failed");
    return;
  }

  if (!rem->response_checked) {
    TSParseResult const res = rem->response.populateFrom(rem->parser, rem->upstream.m_read.m_reader, TSHttpHdrParseResp, nullptr);
    if (TS_PARSE_DONE == res) {
      BlockCheck const check = check_block(rem);
      if (BlockCheck::Match != check) {
        if (BlockCheck::NewVersion == check) {
          repair_first_block(rem);
        }
        fail_remainder(contp, rem, "remainder does not continue the first block");
        return;
      }
      rem->response_checked = true;
      // cache_range_requests marks a block it fetches to store; any other block can end with the window.
      HttpHeader const resp(rem->response.m_buffer, rem->response.m_lochdr);
      if (rem->target < rem->fetch_end && !resp.hasKey(SLICE_CRR_HEADER.data(), SLICE_CRR_HEADER.size())) {
        DEBUG_LOG("Block at %" PRId64 " is not being stored, stopping at the end of the range", rem->fetch_beg);
        rem->stop_early = true;
      }
    } else if (TS_PARSE_ERROR == res || rem->upstream_eos) {
      fail_remainder(contp, rem, "unreadable remainder response header");
      return;
    } else {
      TSVIOReenable(rem->upstream.m_read.m_vio);
      return;
    }
  }

  pump_remainder(contp, rem);
}

int
remainder_handler(TSCont contp, TSEvent event, void *edata)
{
  Remainder *const rem = static_cast<Remainder *>(TSContDataGet(contp));

  if (TSVConnClosedGet(contp)) {
    delete rem;
    TSContDestroy(contp);
    return 0;
  }

  if (rem->failed) {
    return 0;
  }

  if (nullptr != edata && edata == rem->upstream.m_read.m_vio) {
    on_remainder_read(contp, rem, event);
  } else if (nullptr != edata && edata == rem->upstream.m_write.m_vio) {
    if (TS_EVENT_VCONN_WRITE_COMPLETE != event && TS_EVENT_VCONN_WRITE_READY != event) {
      fail_remainder(contp, rem, "could not send the remainder request");
    }
  } else if (nullptr != edata && edata == rem->out_vio) {
    switch (event) {
    case TS_EVENT_VCONN_WRITE_READY:
      pump_remainder(contp, rem);
      break;
    case TS_EVENT_VCONN_WRITE_COMPLETE:
      TSVConnShutdown(TSTransformOutputVConnGet(contp), 0, 1);
      break;
    default:
      fail_remainder(contp, rem, "client side of the transform failed");
      break;
    }
  } else if (TS_EVENT_ERROR == event) {
    // The producer of the first block failed.
    fail_remainder(contp, rem, "first block failed");
  } else {
    pump_remainder(contp, rem);
  }

  return 0;
}

// The base of every block request: the client request without its Range, for the pristine URL. Each block request
// sets its own Range.
bool
build_remainder_request(TSHttpTxn txnp, Config *const config, Remainder *const rem)
{
  rem->config = config;

  TxnHdrMgr client;
  if (!client.populateFrom(txnp, TSHttpTxnClientReqGet)) {
    return false;
  }

  rem->request.m_buffer = TSMBufferCreate();
  if (TS_SUCCESS != TSHttpHdrClone(rem->request.m_buffer, client.m_buffer, client.m_lochdr, &rem->request.m_lochdr)) {
    return false;
  }

  HttpHeader req(rem->request.m_buffer, rem->request.m_lochdr);

  TSMBuffer urlbuf = nullptr;
  TSMLoc    urlloc = nullptr;
  if (TS_SUCCESS != TSHttpTxnPristineUrlGet(txnp, &urlbuf, &urlloc)) {
    return false;
  }
  bool const url_set = req.setUrl(urlbuf, urlloc);
  int        urllen  = 0;
  char      *urlstr  = TSUrlStringGet(urlbuf, urlloc, &urllen);
  if (nullptr != urlstr) {
    rem->url.assign(urlstr, urllen);
    TSfree(urlstr);
  }
  TSHandleMLocRelease(urlbuf, TS_NULL_MLOC, urlloc);
  if (!url_set) {
    return false;
  }

  req.removeKey(config->m_skip_header.data(), config->m_skip_header.size());
  req.removeKey(SLICE_CRR_HEADER.data(), SLICE_CRR_HEADER.size());
  req.removeKey(TS_MIME_FIELD_CONTENT_LENGTH, TS_MIME_LEN_CONTENT_LENGTH);
  req.removeKey(TS_MIME_FIELD_TRANSFER_ENCODING, TS_MIME_LEN_TRANSFER_ENCODING);
  req.removeKey(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE);

  sockaddr const *const ip = TSHttpTxnClientAddrGet(txnp);
  if (nullptr == ip) {
    return false;
  }
  if (AF_INET == ip->sa_family) {
    memcpy(&rem->client_ip, ip, sizeof(sockaddr_in));
  } else if (AF_INET6 == ip->sa_family) {
    memcpy(&rem->client_ip, ip, sizeof(sockaddr_in6));
  } else if (AF_UNIX == ip->sa_family) {
    memcpy(&rem->client_ip, ip, sizeof(sockaddr_un));
  } else {
    return false;
  }

  rem->buffer_index      = TSPluginVCIOBufferIndexGet(txnp);
  rem->buffer_water_mark = TSPluginVCIOBufferWaterMarkGet(txnp);
  return true;
}

bool
add_transform(TSHttpTxn txnp, InlineTxn *const state)
{
  if (state->transform_added) {
    return true;
  }
  auto rem        = std::make_unique<Remainder>();
  rem->txnp       = txnp;
  rem->want       = state->want;
  rem->block_beg  = state->block_beg;
  rem->copy_total = state->copy ? state->total : -1;
  if (!build_remainder_request(txnp, state->config, rem.get())) {
    return false;
  }
  TSVConn const contp = TSTransformCreate(remainder_handler, txnp);
  if (nullptr == contp) {
    return false;
  }
  TSContDataSet(contp, rem.release());
  TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, contp);
  // The cache keeps the first block as cache_range_requests stores it. Without this, core would also store the
  // transformed whole object under the block's key, on a hit as well as on a miss.
  TSHttpTxnTransformedRespCache(txnp, 0);
  TSHttpTxnUntransformedRespCache(txnp, 1);
  state->transform_added = true;
  return true;
}

void
add_send_hook(TSHttpTxn txnp, TSCont contp, InlineTxn *const state)
{
  // Added after remap, when cache_range_requests added its own, so this one runs after it.
  if (!state->send_hook_added) {
    TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_RESPONSE_HDR_HOOK, contp);
    state->send_hook_added = true;
  }
}

void
remember_large(InlineTxn *const state, int64_t const total)
{
  if (!state->url.empty() && total > state->config->m_blockbytes) {
    state->config->sizeCacheAdd(state->url, static_cast<uint64_t>(total));
  }
}

/** A client range that lies inside a fresh cached block [beg, end) of the object: give core the range within the
  block's body, so that it reads only those bytes from the cache, instead of passing the whole block through the
  transform. The send hook rewrites core's Content-Range, which counts from the start of the block.
 */
bool
serve_from_block(TSHttpTxn txnp, InlineTxn *const state, int64_t const beg, int64_t const end, int64_t const total)
{
  if (!state->want.range || !state->want.satisfiable(total) || end < state->want.hi(total)) {
    return false;
  }
  // Core serves a range of a block that another transaction is still writing only from what is written so far; with
  // read_while_writer 2 it sends a range past that to the origin instead, uncached. The transform waits for the writer.
  TSMgmtInt rww = 0;
  if (TS_SUCCESS == TSHttpTxnInfoIntGet(txnp, TS_TXN_INFO_CACHE_HIT_RWW, &rww) && 0 != rww) {
    DEBUG_LOG("Cached block at %" PRId64 " is still being written, reading it whole", beg);
    return false;
  }
  TxnHdrMgr req;
  if (!req.populateFrom(txnp, TSHttpTxnClientReqGet)) {
    return false;
  }
  // Core serves ranges only to HTTP/1.1 requests; it converts HTTP/2 and HTTP/3 requests to HTTP/1.1.
  if (TS_HTTP_VERSION(1, 1) != TSHttpHdrVersionGet(req.m_buffer, req.m_lochdr)) {
    return false;
  }
  char      rangestr[64];
  int const rangelen =
    snprintf(rangestr, sizeof(rangestr), "bytes=%" PRId64 "-%" PRId64, state->want.beg - beg, state->want.hi(total) - 1 - beg);
  HttpHeader(req.m_buffer, req.m_lochdr).setKeyVal(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE, rangestr, rangelen);
  state->block_range = true;
  state->block_end   = end;
  state->total       = total;
  DEBUG_LOG("Serving %.*s of the cached block at %" PRId64, rangelen, rangestr, beg);
  return true;
}

/** Whether upstream got the first block's Range. When the block will not be stored, for example because cache_promote
  did not promote the object, cache_range_requests sends the client's own request instead, and its response reaches
  the client unchanged.
 */
bool
requested_block(TSHttpTxn txnp, InlineTxn const *const state)
{
  TxnHdrMgr req;
  if (!req.populateFrom(txnp, TSHttpTxnServerReqGet)) {
    return true;
  }
  Range const block(state->block_beg, state->block_beg + state->config->m_blockbytes);
  char        blockstr[64];
  int         blocklen = sizeof(blockstr);
  return !block.toStringClosed(blockstr, &blocklen) ||
         field_value(req.m_buffer, req.m_lochdr, TS_MIME_FIELD_RANGE) == std::string_view{blockstr, static_cast<size_t>(blocklen)};
}

/** A fresh complete copy of the object holds the window at the window's own offsets: core serves the window from it
  as from a block that starts at byte 0. Returns whether the cached response is such a copy and holds the start of the
  window.
 */
bool
serve_from_copy(TSHttpTxn txnp, InlineTxn *const state, int const status, TxnHdrMgr const &cached)
{
  int64_t          total = -1;
  std::string_view cl    = field_value(cached.m_buffer, cached.m_lochdr, TS_MIME_FIELD_CONTENT_LENGTH);
  if (TS_CACHE_LOOKUP_HIT_FRESH != status || !parse_count(cl, total) || !cl.empty() ||
      !field_value(cached.m_buffer, cached.m_lochdr, TS_MIME_FIELD_CONTENT_RANGE).empty()) {
    return false;
  }
  if (state->want.range && !state->want.satisfiable(total)) {
    DEBUG_LOG("%s starts past the end of the complete copy", state->client_range.c_str());
    return false;
  }
  DEBUG_LOG("Serving %s from the complete copy", state->want.range ? state->client_range.c_str() : "the whole object");
  if (!state->want.range) {
    return true;
  }
  int64_t const block_beg = state->block_beg;
  state->block_beg        = 0;
  if (serve_from_block(txnp, state, 0, total, total)) {
    return true;
  }
  // Core cannot serve the range from the copy by itself, so the transform cuts it out.
  state->copy  = true;
  state->total = total;
  if (add_transform(txnp, state)) {
    DEBUG_LOG("Cutting %s out of the complete copy", state->client_range.c_str());
    return true;
  }
  state->copy      = false;
  state->block_beg = block_beg;
  return false;
}

// A cached first block, fresh or stale, stored by cache_range_requests as a 200 that keeps the block's Content-Range.
void
on_cache_lookup(TSHttpTxn txnp, TSCont contp, InlineTxn *const state)
{
  add_send_hook(txnp, contp, state);

  int status = 0;
  if (TS_SUCCESS != TSHttpTxnCacheLookupStatusGet(txnp, &status)) {
    return;
  }

  // The second lookup found an object under the URL's own key. Unless it is a complete copy that holds the window,
  // the request continues as the miss of its first block.
  if (state->relookup) {
    state->relookup = false;
    TxnHdrMgr cached;
    if (!cached.populateFrom(txnp, TSHttpTxnCachedRespGet) || !serve_from_copy(txnp, state, status, cached)) {
      DEBUG_LOG("No complete copy under the URL's own key, fetching the block at %" PRId64, state->block_beg);
      TSHttpTxnCacheLookupStatusSet(txnp, TS_CACHE_LOOKUP_MISS);
    }
    return;
  }
  if (TS_CACHE_LOOKUP_MISS == status || TS_CACHE_LOOKUP_SKIPPED == status) {
    TSHttpTxnHookAdd(txnp, TS_HTTP_SEND_REQUEST_HDR_HOOK, contp);
  }
  int64_t blockbeg = 0;
  if (TS_CACHE_LOOKUP_MISS == status && look_up_url_key(txnp, state->config, blockbeg)) {
    state->relookup = true;
    return;
  }
  if (TS_CACHE_LOOKUP_HIT_FRESH != status && TS_CACHE_LOOKUP_HIT_STALE != status) {
    return;
  }

  TxnHdrMgr cached;
  if (!cached.populateFrom(txnp, TSHttpTxnCachedRespGet)) {
    return;
  }

  std::string_view const cr = field_value(cached.m_buffer, cached.m_lochdr, TS_MIME_FIELD_CONTENT_RANGE);
  if (cr.empty()) {
    // A complete response stored under the block's key: it is the whole object.
    if (!serve_from_copy(txnp, state, status, cached) && TS_CACHE_LOOKUP_HIT_FRESH == status) {
      TSHttpTxnCacheLookupStatusSet(txnp, TS_CACHE_LOOKUP_MISS);
    }
    return;
  }

  int64_t beg = 0, end = 0, total = 0;
  if (!parse_content_range(cr, beg, end, total) || state->block_beg != beg) {
    DEBUG_LOG("Unusable cached first block, refetching");
    TSHttpTxnCacheLookupStatusSet(txnp, TS_CACHE_LOOKUP_MISS);
    return;
  }
  remember_large(state, total);
  if (state->want.matches(beg, end, total) ||
      (TS_CACHE_LOOKUP_HIT_FRESH == status && serve_from_block(txnp, state, beg, end, total))) {
    return;
  }
  // A stale block may still be what core serves, if revalidation fails, so the transform is needed now.
  add_transform(txnp, state);
}

// Runs before cache_range_requests' hook, so the status is still the upstream's.
TSEvent
on_server_response(TSHttpTxn txnp, TSCont contp, InlineTxn *const state)
{
  add_send_hook(txnp, contp, state);
  note_block_answer(txnp, state->config);
  state->pass_through = !requested_block(txnp, state);
  if (state->pass_through) {
    return TS_EVENT_HTTP_CONTINUE;
  }

  TxnHdrMgr resp;
  if (!resp.populateFrom(txnp, TSHttpTxnServerRespGet)) {
    return TS_EVENT_HTTP_CONTINUE;
  }

  TSHttpStatus const status = TSHttpHdrStatusGet(resp.m_buffer, resp.m_lochdr);

  // A plugin that runs after slice at cache lookup made the fresh block stale. After a 304 core serves the stored
  // block, still by the range within it; anything else goes through the transform, without core's range handling.
  if (state->block_range && TS_HTTP_STATUS_NOT_MODIFIED != status) {
    TxnHdrMgr req;
    if (req.populateFrom(txnp, TSHttpTxnClientReqGet)) {
      HttpHeader(req.m_buffer, req.m_lochdr).removeKey(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE);
    }
    state->block_range = false;
    if (!add_transform(txnp, state)) {
      TSHttpTxnStatusSet(txnp, TS_HTTP_STATUS_BAD_GATEWAY);
      return TS_EVENT_HTTP_ERROR;
    }
  }

  if (TS_HTTP_STATUS_PARTIAL_CONTENT == status) {
    int64_t beg = 0, end = 0, total = 0;
    if (!parse_content_range(field_value(resp.m_buffer, resp.m_lochdr, TS_MIME_FIELD_CONTENT_RANGE), beg, end, total) ||
        state->block_beg != beg) {
      ERROR_LOG("Inline first block: unusable 206 Content-Range from upstream");
      TSHttpTxnStatusSet(txnp, TS_HTTP_STATUS_BAD_GATEWAY);
      return TS_EVENT_HTTP_ERROR;
    }
    // Slice reads blocks back from the cache and expects each one to be complete.
    if (end != std::min<int64_t>(beg + state->config->m_blockbytes, total)) {
      DEBUG_LOG("First block is %" PRId64 " bytes, not storing it", end);
      TSHttpTxnServerRespNoStoreSet(txnp, 1);
    }
    remember_large(state, total);
    if (!state->want.matches(beg, end, total) && !add_transform(txnp, state)) {
      TSHttpTxnStatusSet(txnp, TS_HTTP_STATUS_BAD_GATEWAY);
      return TS_EVENT_HTTP_ERROR;
    }
  } else if (TS_HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE == status && !state->want.range) {
    int64_t total = -1;
    if (!parse_unsatisfied_range(field_value(resp.m_buffer, resp.m_lochdr, TS_MIME_FIELD_CONTENT_RANGE), total) || 0 != total) {
      ERROR_LOG("Inline first block: 416 for a range that starts at byte 0");
      TSHttpTxnStatusSet(txnp, TS_HTTP_STATUS_BAD_GATEWAY);
      return TS_EVENT_HTTP_ERROR;
    }
    // The transform drops the 416 body; the send hook turns the response into an empty 200.
    if (!add_transform(txnp, state)) {
      TSHttpTxnStatusSet(txnp, TS_HTTP_STATUS_BAD_GATEWAY);
      return TS_EVENT_HTTP_ERROR;
    }
    TSHttpTxnServerRespNoStoreSet(txnp, 1);
  }
  // 200 (the upstream ignored Range), 304, a 416 for a client range, and every other status reach the client as
  // core serves them.
  return TS_EVENT_HTTP_CONTINUE;
}

// The client request carries the block's Range and the skip header; put back what the client sent, for logging.
void
restore_client_request(TSHttpTxn txnp, InlineTxn const *const state)
{
  TxnHdrMgr req;
  if (!req.populateFrom(txnp, TSHttpTxnClientReqGet)) {
    return;
  }
  HttpHeader request(req.m_buffer, req.m_lochdr);
  if (state->want.range) {
    request.setKeyVal(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE, state->client_range.data(), state->client_range.size());
  } else {
    request.removeKey(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE);
  }
  request.removeKey(state->config->m_skip_header.data(), state->config->m_skip_header.size());
}

/** Make the response that core serves the response to the client's request: a 200 for a whole-object GET, a 206 for
  the client's range, or a 416 for a range past the end.

  It sees the response after cache_range_requests restored a block's 206.
 */
TSEvent
on_send_response(TSHttpTxn txnp, InlineTxn *const state)
{
  restore_client_request(txnp, state);
  if (state->pass_through) {
    return TS_EVENT_HTTP_CONTINUE;
  }

  TxnHdrMgr resp;
  if (!resp.populateFrom(txnp, TSHttpTxnClientRespGet)) {
    return TS_EVENT_HTTP_CONTINUE;
  }
  HttpHeader         header(resp.m_buffer, resp.m_lochdr);
  TSHttpStatus const status = header.status();
  std::string_view   cr     = field_value(resp.m_buffer, resp.m_lochdr, TS_MIME_FIELD_CONTENT_RANGE);
  int64_t            s = 0, e = 0, total = 0;
  TSHttpStatus       out_status = TS_HTTP_STATUS_OK;
  char               crstr[96];
  int                crlen = 0;

  auto close = [txnp](char const *const why) {
    ERROR_LOG("Inline first block: %s, closing", why);
    TSHttpTxnShutDown(txnp, TS_EVENT_HTTP_ERROR);
    return TS_EVENT_HTTP_ERROR;
  };
  auto length = [&resp]() {
    int64_t          n  = -1;
    std::string_view cl = field_value(resp.m_buffer, resp.m_lochdr, TS_MIME_FIELD_CONTENT_LENGTH);
    return parse_count(cl, n) && cl.empty() ? n : -1;
  };

  if (state->block_range) {
    // Core served the window from the cached block; its Content-Range counts from the start of the block.
    int64_t const lo = state->want.beg - state->block_beg;
    int64_t const hi = state->want.hi(state->total) - state->block_beg;
    if (TS_HTTP_STATUS_PARTIAL_CONTENT != status || !parse_content_range(cr, s, e, total) || lo != s || hi != e ||
        state->block_end - state->block_beg != total || length() != hi - lo) {
      return close("core did not serve the range within the cached block");
    }
    crlen = snprintf(crstr, sizeof(crstr), "bytes %" PRId64 "-%" PRId64 "/%" PRId64, state->want.beg,
                     state->want.hi(state->total) - 1, state->total);
    header.setKeyVal(TS_MIME_FIELD_CONTENT_RANGE, TS_MIME_LEN_CONTENT_RANGE, crstr, crlen);
    return TS_EVENT_HTTP_CONTINUE;
  }

  if (TS_HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE == status) {
    // Only an empty object's 416, for a whole-object GET, went through the transform, which produced no body.
    if (state->want.range || !state->transform_added || !parse_unsatisfied_range(cr, total) || 0 != total) {
      return TS_EVENT_HTTP_CONTINUE;
    }
  } else if (TS_HTTP_STATUS_PARTIAL_CONTENT == status || TS_HTTP_STATUS_OK == status) {
    if (cr.empty()) {
      if (!state->copy) {
        return TS_EVENT_HTTP_CONTINUE;
      }
      // The transform cut the window out of a complete copy.
      e     = state->total;
      total = state->total;
    } else if (!parse_content_range(cr, s, e, total) || state->block_beg != s) {
      return close("unusable Content-Range in the response");
    }
    if (!state->want.satisfiable(total)) {
      // The transform produced no body.
      if (0 != length()) {
        return close("body for a range past the end");
      }
      out_status = TS_HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE;
      crlen      = snprintf(crstr, sizeof(crstr), "bytes */%" PRId64, total);
    } else {
      int64_t const lo = state->want.beg;
      int64_t const hi = state->want.hi(total);
      // Unless the block is already the client's response, only the transform makes it so, and it declared the
      // length.
      if (!state->want.matches(s, e, total) && length() != hi - lo) {
        return close("response length does not match the client's window");
      }
      if (state->want.range) {
        out_status = TS_HTTP_STATUS_PARTIAL_CONTENT;
        crlen      = snprintf(crstr, sizeof(crstr), "bytes %" PRId64 "-%" PRId64 "/%" PRId64, lo, hi - 1, total);
      }
    }
  } else {
    return TS_EVENT_HTTP_CONTINUE;
  }

  header.setStatus(out_status);
  char const *const reason = TSHttpHdrReasonLookup(out_status);
  header.setReason(reason, strlen(reason));
  if (0 < crlen) {
    header.setKeyVal(TS_MIME_FIELD_CONTENT_RANGE, TS_MIME_LEN_CONTENT_RANGE, crstr, crlen);
  } else {
    header.removeKey(TS_MIME_FIELD_CONTENT_RANGE, TS_MIME_LEN_CONTENT_RANGE);
  }
  return TS_EVENT_HTTP_CONTINUE;
}

int
inline_txn_handler(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn const  txnp     = static_cast<TSHttpTxn>(edata);
  InlineTxn *const state    = static_cast<InlineTxn *>(TSContDataGet(contp));
  TSEvent          reenable = TS_EVENT_HTTP_CONTINUE;

  switch (event) {
  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
    on_cache_lookup(txnp, contp, state);
    break;
  case TS_EVENT_HTTP_SEND_REQUEST_HDR:
    unmark_unstored_request(txnp, state->config);
    break;
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    reenable = on_server_response(txnp, contp, state);
    break;
  case TS_EVENT_HTTP_SEND_RESPONSE_HDR:
    reenable = on_send_response(txnp, state);
    break;
  case TS_EVENT_HTTP_TXN_CLOSE:
    delete state;
    TSContDestroy(contp);
    break;
  default:
    break;
  }

  TSHttpTxnReenable(txnp, reenable);
  return 0;
}

} // namespace

bool
inline_first_block(TSHttpTxn txnp, Config *const config, HttpHeader &header)
{
  if (TS_HTTP_METHOD_GET != header.method()) {
    return false;
  }
  // Core answers conditional requests from the stored block, which would bypass the conversion.
  if (header.hasKey(TS_MIME_FIELD_IF_MATCH, TS_MIME_LEN_IF_MATCH) ||
      header.hasKey(TS_MIME_FIELD_IF_NONE_MATCH, TS_MIME_LEN_IF_NONE_MATCH) ||
      header.hasKey(TS_MIME_FIELD_IF_MODIFIED_SINCE, TS_MIME_LEN_IF_MODIFIED_SINCE) ||
      header.hasKey(TS_MIME_FIELD_IF_UNMODIFIED_SINCE, TS_MIME_LEN_IF_UNMODIFIED_SINCE) ||
      header.hasKey(TS_MIME_FIELD_IF_RANGE, TS_MIME_LEN_IF_RANGE)) {
    return false;
  }

  auto state    = std::make_unique<InlineTxn>();
  state->config = config;

  // One range with a start: bytes=a-b or bytes=a-. A suffix range needs the object's length to find its block, and a
  // multi-range request does not parse; both are sliced.
  if (header.hasKey(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE)) {
    char  rangestr[1024];
    int   rangelen = sizeof(rangestr);
    Range client;
    if (!header.valueForKey(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE, rangestr, &rangelen) || !client.fromStringClosed(rangestr) ||
        client.isEndBytes()) {
      return false;
    }
    state->want = Window{client.m_beg, client.m_end, true};
    state->client_range.assign(rangestr, rangelen);
  }

  if (!state->want.range && config->hasSizeCache()) {
    int                                      len = 0;
    std::unique_ptr<char, decltype(&TSfree)> urlstr(TSHttpTxnEffectiveUrlStringGet(txnp, &len), TSfree);
    if (nullptr != urlstr) {
      state->url.assign(urlstr.get(), len);
      std::optional<uint64_t> const size = config->sizeCacheGet(state->url);
      if (size.has_value() && *size > static_cast<uint64_t>(config->m_blockbytes)) {
        DEBUG_LOG("Known large object, slicing: %s", state->url.c_str());
        return false;
      }
    }
  }

  // The request for the block that holds the window's first byte, as request_block() forms it, with the skip header
  // that handle_client_req() sets.
  state->block_beg = state->want.beg / config->m_blockbytes * config->m_blockbytes;
  Range const block(state->block_beg, state->block_beg + config->m_blockbytes);
  char        blockstr[64];
  int         blocklen = sizeof(blockstr);
  if (!block.toStringClosed(blockstr, &blocklen)) {
    return false;
  }
  header.setKeyVal(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE, blockstr, blocklen);
  if (state->want.range) {
    header.setKeyVal(config->m_skip_header.data(), config->m_skip_header.size(), state->client_range.data(),
                     state->client_range.size());
  } else {
    header.setKeyVal(config->m_skip_header.data(), config->m_skip_header.size(), "-", 1);
  }
  header.removeKey(SLICE_CRR_HEADER.data(), SLICE_CRR_HEADER.size());
  // cache_range_requests sends the client's own request instead of a block that will not be stored.
  if (state->want.range) {
    header.setKeyVal(SLICE_UNSTORED_HEADER.data(), SLICE_UNSTORED_HEADER.size(), state->client_range.data(),
                     state->client_range.size());
  } else {
    header.setKeyVal(SLICE_UNSTORED_HEADER.data(), SLICE_UNSTORED_HEADER.size(), "-", 1);
  }

  TSCont const contp = TSContCreate(inline_txn_handler, nullptr);
  TSContDataSet(contp, state.release());
  TSHttpTxnHookAdd(txnp, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, contp);
  DEBUG_LOG("Inline first block: %.*s", blocklen, blockstr);
  return true;
}

bool
serve_window_from_copy(TSHttpTxn txnp, Config *const config, Range const &want, int64_t const total, std::string_view const range)
{
  auto state          = std::make_unique<InlineTxn>();
  state->config       = config;
  state->want         = want.isEndBytes() ? Window{std::max<int64_t>(0, total + want.m_beg), Range::maxval, true} :
                                            Window{want.m_beg, want.m_end, true};
  state->client_range = range;
  state->copy         = true;
  state->total        = total;
  if (!add_transform(txnp, state.get())) {
    return false;
  }
  DEBUG_LOG("Cutting %.*s out of the complete copy", static_cast<int>(range.size()), range.data());
  TSCont const contp = TSContCreate(inline_txn_handler, nullptr);
  add_send_hook(txnp, contp, state.get());
  TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, contp);
  TSContDataSet(contp, state.release());
  return true;
}
