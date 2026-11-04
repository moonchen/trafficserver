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

#include "first_block.h"

#include "Config.h"
#include "HttpHeader.h"
#include "Range.h"
#include "slice.h"

#include <cinttypes>
#include <memory>
#include <string>
#include <string_view>

namespace
{
constexpr char const *SLICE_BLOCK_ARG = "slice.block";
int                   slice_block_arg_idx{-1};
// The argument points to one of these. cache_range_requests stores a complete response (a 200) of a block request
// under the request's cache key only for slice_whole_mark, or when the request is for block 0.
char slice_block_mark{'b'};
char slice_whole_mark{'w'};
// A first block request that looks for the complete copy under block 0's key.
char slice_relookup_mark{'l'};

void
set_mark(TSHttpTxn txnp, char *const mark)
{
  if (0 <= slice_block_arg_idx) {
    TSUserArgSet(txnp, slice_block_arg_idx, mark);
  }
}

bool
has_mark(TSHttpTxn txnp, char const *const mark)
{
  return 0 <= slice_block_arg_idx && mark == TSUserArgGet(txnp, slice_block_arg_idx);
}

// The client's Range, which the skip header carries to the block transaction, or empty for a whole-object GET.
std::string_view
client_range_of(HttpHeader const &request, Config const *const config, char *const buf, int const buflen)
{
  int len = buflen;
  if (!request.valueForKey(config->m_skip_header.data(), config->m_skip_header.size(), buf, &len)) {
    return {};
  }
  std::string_view const range{buf, static_cast<size_t>(len)};
  return "-" == range ? std::string_view{} : range;
}

/** A complete copy under the block's key (a 200 without Content-Range) holds the client's range at the range's own
  offsets. Core serves that range from it, as it serves a range of an object that is not sliced.
 */
bool
serve_client_range_from_copy(TSHttpTxn txnp, Config const *const config)
{
  TxnHdrMgr cached;
  if (!cached.populateFrom(txnp, TSHttpTxnCachedRespGet)) {
    return false;
  }
  HttpHeader const copy(cached.m_buffer, cached.m_lochdr);
  if (TS_HTTP_STATUS_OK != copy.status() || copy.hasKey(TS_MIME_FIELD_CONTENT_RANGE, TS_MIME_LEN_CONTENT_RANGE)) {
    return false;
  }

  TxnHdrMgr req;
  if (!req.populateFrom(txnp, TSHttpTxnClientReqGet)) {
    return false;
  }
  HttpHeader request(req.m_buffer, req.m_lochdr);
  // Core serves ranges only to HTTP/1.1 requests.
  if (TS_HTTP_VERSION(1, 1) != request.version()) {
    return false;
  }
  char                   rangestr[1024];
  std::string_view const range = client_range_of(request, config, rangestr, sizeof(rangestr));
  if (range.empty()) {
    return false;
  }
  DEBUG_LOG("Serving %.*s from the complete copy", static_cast<int>(range.size()), range.data());
  return request.setKeyVal(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE, range.data(), range.size());
}

/** cache_range_requests keys a block as <URL>-<the block's Range>. If the transaction's cache key is a block's key,
  return that block's number and the key of block @a target of the same object.
 */
bool
block_key(TSHttpTxn txnp, Config const *const config, int64_t const target, int64_t &blocknum, std::string &key)
{
  TSMBuffer const buf = TSMBufferCreate();
  TSMLoc          loc = TS_NULL_MLOC;
  bool            got = false;
  if (TS_SUCCESS == TSUrlCreate(buf, &loc) && TS_SUCCESS == TSHttpTxnCacheLookupUrlGet(txnp, buf, loc)) {
    int         len = 0;
    char *const str = TSUrlStringGet(buf, loc, &len);
    if (nullptr != str) {
      key.assign(str, len);
      got = true;
      TSfree(str);
    }
  }
  if (TS_NULL_MLOC != loc) {
    TSHandleMLocRelease(buf, TS_NULL_MLOC, loc);
  }
  TSMBufferDestroy(buf);

  int64_t const     blockbytes = config->m_blockbytes;
  std::size_t const dash       = got ? key.rfind("-bytes=") : std::string::npos;
  Range             block;
  if (std::string::npos == dash || !block.fromStringClosed(key.c_str() + dash + 1) || 0 != block.m_beg % blockbytes ||
      blockbytes != block.m_end - block.m_beg) {
    return false;
  }
  blocknum = block.m_beg / blockbytes;

  char rangestr[64];
  int  rangelen = sizeof(rangestr);
  if (!Range(target * blockbytes, (target + 1) * blockbytes).toStringClosed(rangestr, &rangelen)) {
    return false;
  }
  key.resize(dash + 1);
  key.append(rangestr, rangelen);
  return true;
}

void
on_first_block_lookup(TSHttpTxn txnp, TSCont contp, Config const *const config)
{
  int status = 0;
  if (TS_SUCCESS != TSHttpTxnCacheLookupStatusGet(txnp, &status)) {
    return;
  }

  // The second lookup found an object under block 0's key. Unless it is the complete copy, the block request continues
  // as the miss of its own block, with the hook that the miss added.
  if (has_mark(txnp, &slice_relookup_mark)) {
    set_mark(txnp, &slice_block_mark);
    if (TS_CACHE_LOOKUP_HIT_FRESH != status || !serve_client_range_from_copy(txnp, config)) {
      DEBUG_LOG("No complete copy under block 0's key");
      TSHttpTxnCacheLookupStatusSet(txnp, TS_CACHE_LOOKUP_MISS);
    }
    return;
  }

  if (TS_CACHE_LOOKUP_MISS == status || TS_CACHE_LOOKUP_SKIPPED == status) {
    if (config->firstBlockVaries()) {
      TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
      if (TS_CACHE_LOOKUP_MISS == status && look_up_whole_copy(txnp, config)) {
        set_mark(txnp, &slice_relookup_mark);
      }
    }
  } else if (TS_CACHE_LOOKUP_HIT_FRESH == status && serve_client_range_from_copy(txnp, config)) {
    TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
  }
}

void
on_first_block_response(TSHttpTxn txnp, Config *const config)
{
  note_block_answer(txnp, config);

  // A plugin that runs later at cache lookup made the copy stale. Only after a 304 does core serve the copy, by the
  // client's range; anything else upstream sends must reach slice as it is.
  TxnHdrMgr resp;
  TxnHdrMgr req;
  if (!resp.populateFrom(txnp, TSHttpTxnServerRespGet) ||
      TS_HTTP_STATUS_NOT_MODIFIED == TSHttpHdrStatusGet(resp.m_buffer, resp.m_lochdr) ||
      !req.populateFrom(txnp, TSHttpTxnClientReqGet)) {
    return;
  }
  HttpHeader             request(req.m_buffer, req.m_lochdr);
  char                   clientstr[1024];
  char                   rangestr[1024];
  int                    rangelen = sizeof(rangestr);
  std::string_view const client   = client_range_of(request, config, clientstr, sizeof(clientstr));
  if (!client.empty() && request.valueForKey(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE, rangestr, &rangelen) &&
      client == std::string_view{rangestr, static_cast<size_t>(rangelen)}) {
    request.removeKey(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE);
  }
}

} // namespace

void
reserve_slice_block_arg()
{
  if (TS_SUCCESS != TSUserArgIndexReserve(TS_USER_ARGS_TXN, SLICE_BLOCK_ARG, "slice block request", &slice_block_arg_idx)) {
    ERROR_LOG("Failed to reserve the %s transaction argument", SLICE_BLOCK_ARG);
  }
}

void
mark_slice_block(TSHttpTxn txnp)
{
  set_mark(txnp, &slice_block_mark);
}

bool
look_up_whole_copy(TSHttpTxn txnp, Config const *const config)
{
  int64_t     blocknum = 0;
  std::string key;
  if (!config->m_whole_lookup || !block_key(txnp, config, 0, blocknum, key) || 0 == blocknum ||
      TS_SUCCESS != TSHttpTxnCacheLookupAgain(txnp, key.data(), key.size())) {
    return false;
  }
  DEBUG_LOG("Block %" PRId64 " is not cached, looking for the complete copy under block 0's key", blocknum);
  return true;
}

void
note_block_answer(TSHttpTxn txnp, Config *const config)
{
  if (!config->firstBlockVaries()) {
    return;
  }
  TxnHdrMgr req;
  TxnHdrMgr resp;
  if (!req.populateFrom(txnp, TSHttpTxnServerReqGet) || !resp.populateFrom(txnp, TSHttpTxnServerRespGet)) {
    return;
  }
  HttpHeader const request(req.m_buffer, req.m_lochdr);
  HttpHeader const response(resp.m_buffer, resp.m_lochdr);
  char             rangestr[1024];
  int              rangelen = sizeof(rangestr);
  if (!request.valueForKey(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE, rangestr, &rangelen)) {
    return;
  }

  TSHttpStatus const status = response.status();
  bool const whole = TS_HTTP_STATUS_OK == status && !response.hasKey(TS_MIME_FIELD_CONTENT_RANGE, TS_MIME_LEN_CONTENT_RANGE);
  if (!whole && (TS_HTTP_STATUS_PARTIAL_CONTENT != status || !config->hasWholeObjects())) {
    return;
  }

  int                                      urllen = 0;
  std::unique_ptr<char, decltype(&TSfree)> url(TSHttpTxnEffectiveUrlStringGet(txnp, &urllen), TSfree);
  if (nullptr == url) {
    return;
  }
  std::string_view const urlkey{url.get(), static_cast<size_t>(urllen)};
  if (!whole) {
    config->wholeObjectRemove(urlkey);
    return;
  }

  Range         range;
  int64_t const blocknum  = range.fromStringClosed(rangestr) && 0 <= range.m_beg ? range.m_beg / config->m_blockbytes : 0;
  int64_t       copyblock = 0;
  switch (config->m_whole_copy) {
  case Config::WholeCopy::Block0:
    break;
  case Config::WholeCopy::Own:
    copyblock = blocknum;
    set_mark(txnp, &slice_whole_mark);
    break;
  case Config::WholeCopy::Move: {
    int64_t     keyblock = 0;
    std::string block0;
    if (0 < blocknum && block_key(txnp, config, 0, keyblock, block0) && keyblock == blocknum &&
        TS_SUCCESS == TSHttpTxnCacheWriteUrlSet(txnp, block0.data(), block0.size())) {
      DEBUG_LOG("Moving the cache write of the whole object from block %" PRId64 " to block 0's key", blocknum);
      set_mark(txnp, &slice_whole_mark);
    }
  } break;
  }
  config->wholeObjectAdd(urlkey, copyblock);
}

void
watch_block_request(TSHttpTxn txnp, HttpHeader &header, TSCont contp)
{
  if (TS_HTTP_METHOD_GET != header.method()) {
    return;
  }
  mark_slice_block(txnp);
  if (header.hasKey(SLICE_FIRST_BLOCK_HEADER.data(), SLICE_FIRST_BLOCK_HEADER.size())) {
    header.removeKey(SLICE_FIRST_BLOCK_HEADER.data(), SLICE_FIRST_BLOCK_HEADER.size());
    TSHttpTxnHookAdd(txnp, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, contp);
  }
}

int
first_block_handler(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn const txnp   = static_cast<TSHttpTxn>(edata);
  Config *const   config = static_cast<Config *>(TSContDataGet(contp));

  switch (event) {
  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
    on_first_block_lookup(txnp, contp, config);
    break;
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    on_first_block_response(txnp, config);
    break;
  default:
    break;
  }

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return 0;
}
