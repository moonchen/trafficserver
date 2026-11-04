/** @file
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

#include "util.h"
#include "prefetch.h"
#include "HttpHeader.h"

#include "Config.h"
#include "Data.h"
#include "first_block.h"

void
shutdown(TSCont const contp, Data *const data)
{
  DEBUG_LOG("shutting down transaction");
  data->m_upstream.close();
  data->m_dnstream.close();
  TSContDataSet(contp, nullptr);
  delete data;
  TSContDestroy(contp);
}

void
abort(TSCont const contp, Data *const data)
{
  DEBUG_LOG("aborting transaction");
  data->m_upstream.abort();
  data->m_dnstream.abort();
  TSContDataSet(contp, nullptr);
  delete data;
  TSContDestroy(contp);
}

void
schedule_prefetch(Data *const data)
{
  if (!data->m_prefetchable || data->m_config->m_prefetchcount <= 0) {
    return;
  }

  int         urllen = 0;
  char *const urlstr = TSUrlStringGet(data->m_urlbuf, data->m_urlloc, &urllen);

  if (urlstr == nullptr || urllen <= 0) {
    TSfree(urlstr);
    return;
  }

  std::string_view const url(urlstr, urllen);
  int64_t                nextblocknum = data->m_blocknum + 1;

  if (data->m_blocknum > data->m_req_range.firstBlockFor(data->m_config->m_blockbytes) + 1) {
    nextblocknum = data->m_blocknum + data->m_config->m_prefetchcount;
  }

  int64_t const lastblocknum = data->m_blocknum + data->m_config->m_prefetchcount;

  // Skip blocks already scheduled this request; re-issuing them races the inline reads.
  if (nextblocknum <= data->m_prefetch_hwm) {
    nextblocknum = data->m_prefetch_hwm + 1;
  }

  for (int64_t i = nextblocknum; i <= lastblocknum; i++) {
    if (data->m_req_range.blockIsInside(data->m_config->m_blockbytes, i)) {
      if (BgBlockFetch::schedule(data, static_cast<int>(i), url)) {
        DEBUG_LOG("Background fetch requested");
      } else {
        DEBUG_LOG("Background fetch not requested");
      }
    }
  }

  if (lastblocknum > data->m_prefetch_hwm) {
    data->m_prefetch_hwm = lastblocknum;
  }

  TSfree(urlstr);
}

// create and issue a block request
bool
request_block(TSCont contp, Data *const data)
{
  // ensure no upstream connection
  if (data->m_upstream.m_read.isOpen()) {
    ERROR_LOG("Block request already in flight!");
    return false;
  }

  switch (data->m_blockstate) {
  case BlockState::Pending:
  case BlockState::PendingRef:
    break;
  default:
    ERROR_LOG("request_block called with non Pending* state!");
    return false;
    break;
  }

  int64_t const blockbeg = (data->m_config->m_blockbytes * data->m_blocknum);
  Range         blockbe(blockbeg, blockbeg + data->m_config->m_blockbytes);

  char       rangestr[1024];
  int        rangelen = sizeof(rangestr);
  bool const rpstat   = blockbe.toStringClosed(rangestr, &rangelen);
  TSAssert(rpstat);

  DEBUG_LOG("requestBlock: %s", rangestr);

  // reuse the original client request header, just change the range
  HttpHeader header(data->m_req_hdrmgr.m_buffer, data->m_req_hdrmgr.m_lochdr);

  // if configured, remove range header from head requests. A purge without Range removes the copy of an object that
  // is stored under the URL's own key.
  if ((data->m_method_type == TS_HTTP_METHOD_HEAD && data->m_config->m_head_strip_range) || data->m_purge_url_key) {
    header.removeKey(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE);
  } else {
    // add/set sub range key and add slicer tag
    bool const rangestat = header.setKeyVal(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE, rangestr, rangelen);

    if (!rangestat) {
      ERROR_LOG("Error trying to set range request header %s", rangestr);
      return false;
    }
  }

  header.removeKey(SLICE_CRR_HEADER.data(), SLICE_CRR_HEADER.size());
  if (!data->is_purge() && data->m_config->m_prefetchcount > 0 && data->m_req_range.m_beg >= 0 &&
      data->m_blocknum == data->m_req_range.firstBlockFor(data->m_config->m_blockbytes)) {
    header.setKeyVal(SLICE_CRR_HEADER.data(), SLICE_CRR_HEADER.size(), SLICE_CRR_VAL.data(), SLICE_CRR_VAL.size());
  }

  // Attach the identifier header
  // The cache_range_requests plugin will:
  //   mark a fresh block stale if the identifiers mismatch
  //   mark a stale block fresh if the identifiers match.
  Config const *const cfg = data->m_config;
  if (!cfg->m_crr_ident_header.empty()) {
    // Set ident header if header not set or if refetch reference slice
    if (BlockState::PendingRef == data->m_blockstate ||
        !header.hasKey(cfg->m_crr_ident_header.data(), cfg->m_crr_ident_header.size())) {
      swoc::LocalBufferWriter<8192> idbuf;
      if (0 < data->m_etaglen) {
        idbuf.write(TS_MIME_FIELD_ETAG, TS_MIME_LEN_ETAG);
        idbuf.write(" ");
        idbuf.write(data->m_etag, data->m_etaglen);
      } else if (0 < data->m_lastmodifiedlen) {
        idbuf.write(TS_MIME_FIELD_LAST_MODIFIED, TS_MIME_LEN_LAST_MODIFIED);
        idbuf.write(" ");
        idbuf.write(data->m_lastmodified, data->m_lastmodifiedlen);
      } else if (BlockState::PendingRef == data->m_blockstate) {
        idbuf.write("Stale");
      }

      if (0 < idbuf.size()) {
        DEBUG_LOG("Adding identity '%.*s'", (int)idbuf.size(), idbuf.data());
        header.setKeyVal(cfg->m_crr_ident_header.data(), cfg->m_crr_ident_header.size(), idbuf.data(), idbuf.size());
      }
    }
  }

  bool const get         = TS_HTTP_METHOD_GET == data->m_method_type;
  bool const first_block = get && !data->m_server_first_header_parsed && BlockState::Pending == data->m_blockstate &&
                           TS_HTTP_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE != data->m_statustype;
  // The marker tells the block transaction (first_block.cc) that a complete copy of the object serves the client's
  // range rather than the block.
  if (first_block) {
    header.setKeyVal(SLICE_FIRST_BLOCK_HEADER.data(), SLICE_FIRST_BLOCK_HEADER.size(), "1", 1);
  }

  // What cache_range_requests requests instead of the block if it will not be stored: the client's own request for
  // the first block, and the client's part of a later block of which the client needs only part.
  char unstoredstr[1024];
  int  unstoredlen = 0;
  if (first_block) {
    unstoredlen = sizeof(unstoredstr);
    if (!header.valueForKey(cfg->m_skip_header.data(), cfg->m_skip_header.size(), unstoredstr, &unstoredlen)) {
      unstoredlen = 0;
    }
  } else if (get && data->m_server_first_header_parsed && BlockState::Pending == data->m_blockstate) {
    Range const block(blockbeg, std::min(blockbeg + data->m_config->m_blockbytes, data->m_contentlen));
    Range const need = block.intersectedWith(data->m_req_range);
    if (need.isValid() && (block.m_beg < need.m_beg || need.m_end < block.m_end)) {
      unstoredlen = sizeof(unstoredstr);
      if (!need.toStringClosed(unstoredstr, &unstoredlen)) {
        unstoredlen = 0;
      }
    }
  }
  if (0 < unstoredlen) {
    header.setKeyVal(SLICE_UNSTORED_HEADER.data(), SLICE_UNSTORED_HEADER.size(), unstoredstr, unstoredlen);
  }

  // create virtual connection back into ATS
  TSHttpConnectOptions options = TSHttpConnectOptionsGet(TS_CONNECT_PLUGIN);
  options.addr                 = reinterpret_cast<sockaddr *>(&data->m_client_ip);
  options.tag                  = PLUGIN_NAME;
  options.id                   = 0;
  options.buffer_index         = data->m_buffer_index;
  options.buffer_water_mark    = data->m_buffer_water_mark;

  TSVConn const upvc = TSHttpConnectPlugin(&options);

  int const hlen = TSHttpHdrLengthGet(header.m_buffer, header.m_lochdr);

  // set up connection with the HttpConnect server
  data->m_upstream.setupConnection(upvc);
  data->m_upstream.setupVioWrite(contp, hlen);

  // Send full request
  TSHttpHdrPrint(header.m_buffer, header.m_lochdr, data->m_upstream.m_write.m_iobuf);
  TSVIOReenable(data->m_upstream.m_write.m_vio);

  if (dbg_ctl.on()) {
    std::string const headerstr(header.toString());
    DEBUG_LOG("Headers\n%s", headerstr.c_str());
  }

  if (first_block) {
    header.removeKey(SLICE_FIRST_BLOCK_HEADER.data(), SLICE_FIRST_BLOCK_HEADER.size());
  }
  if (0 < unstoredlen) {
    header.removeKey(SLICE_UNSTORED_HEADER.data(), SLICE_UNSTORED_HEADER.size());
  }

  // Extend prefetch sliding window past the initial burst
  if (data->m_blocknum > data->m_req_range.firstBlockFor(data->m_config->m_blockbytes) + 1) {
    schedule_prefetch(data);
  }

  // get ready for data back from the server
  data->m_upstream.setupVioRead(contp, INT64_MAX);

  // anticipate the next server response header
  TSHttpParserClear(data->m_http_parser);
  data->m_resp_hdrmgr.resetHeader();

  data->m_blockexpected              = 0;
  data->m_blockconsumed              = 0;
  data->m_server_block_header_parsed = false;

  switch (data->m_blockstate) {
  case BlockState::Pending:
    data->m_blockstate = BlockState::Active;
    break;
  case BlockState::PendingRef: {
    data->m_blockstate = BlockState::ActiveRef;
  } break;
  default:
    ERROR_LOG("Invalid blockstate");
    return false;
    break;
  }

  return true;
}

bool
reader_avail_more_than(TSIOBufferReader const reader, int64_t bytes)
{
  // A purge refused before opening an upstream has no reader, and TSIOBufferReaderStart
  // does not tolerate a null one
  if (nullptr == reader) {
    return false;
  }

  TSIOBufferBlock block = TSIOBufferReaderStart(reader);

  if (nullptr == block) {
    return false;
  }

  while (nullptr != block) {
    int64_t const blockbytes = TSIOBufferBlockReadAvail(block, reader);
    if (bytes < blockbytes) {
      return true;
    } else {
      bytes -= blockbytes;
    }

    block = TSIOBufferBlockNext(block);
  }

  return false;
}
