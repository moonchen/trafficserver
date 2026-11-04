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
#include "inline.h"
#include "slice.h"

#include <algorithm>
#include <charconv>
#include <cinttypes>
#include <cstdint>
#include <string>
#include <string_view>
#include <strings.h>

namespace
{
constexpr char const *SLICE_BLOCK_ARG = "slice.block";
int                   slice_block_arg_idx{-1};
// The argument points to one of these. cache_range_requests stores a complete response (a 200) of a block request
// under the request's cache key only for whole_mark, or when the request is for block 0.
char block_mark{'b'};
char first_block_mark{'f'}; // the first block of a client request that slice serves through its intercept
char whole_mark{'w'};

// While a block request looks up the URL's own key, this argument holds the first byte of the block plus one.
constexpr char const *SLICE_RELOOKUP_ARG = "slice.relookup";
int                   slice_relookup_arg_idx{-1};

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

bool
lookup_url_string(TSHttpTxn txnp, std::string &key)
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
  return got;
}

/** A block's Range, "bytes=<first>-<last>", at the start of @a sv.

  @param[out] beg the first byte of the block
  @param[out] len the length of the Range in @a sv
 */
bool
parse_block_range(std::string_view const sv, int64_t const blockbytes, int64_t &beg, size_t &len)
{
  constexpr std::string_view bytes = "bytes=";
  if (!sv.starts_with(bytes)) {
    return false;
  }
  char const *const start = sv.data();
  char const *const end   = sv.data() + sv.size();
  int64_t           last  = 0;
  auto const [dash, ec]   = std::from_chars(start + bytes.size(), end, beg);
  if (std::errc() != ec || dash == end || '-' != *dash) {
    return false;
  }
  auto const [stop, lastec] = std::from_chars(dash + 1, end, last);
  if (std::errc() != lastec || beg < 0 || 0 != beg % blockbytes || blockbytes != last - beg + 1) {
    return false;
  }
  len = stop - start;
  return true;
}

// The cached response is a complete copy of the object (a 200 without Content-Range), of total bytes.
bool
complete_copy(TSHttpTxn txnp, int64_t &total)
{
  TxnHdrMgr cached;
  if (!cached.populateFrom(txnp, TSHttpTxnCachedRespGet)) {
    return false;
  }
  HttpHeader const copy(cached.m_buffer, cached.m_lochdr);
  char             clstr[32];
  int              cllen = sizeof(clstr);
  if (TS_HTTP_STATUS_OK != copy.status() || copy.hasKey(TS_MIME_FIELD_CONTENT_RANGE, TS_MIME_LEN_CONTENT_RANGE) ||
      !copy.valueForKey(TS_MIME_FIELD_CONTENT_LENGTH, TS_MIME_LEN_CONTENT_LENGTH, clstr, &cllen)) {
    return false;
  }
  auto const [ptr, ec] = std::from_chars(clstr, clstr + cllen, total);
  return std::errc() == ec && ptr == clstr + cllen && 0 <= total;
}

/** A complete copy holds the request's range at the range's own offsets, so core serves that range from it, as it
  serves a range of an object that is not sliced: the client's range for a first block, nothing for a whole-object
  GET, and the block for a later block. A range that starts at or past the end of the copy is not served from it.

  @param blockbeg the first byte of the block, for a later block
 */
bool
serve_from_copy(TSHttpTxn txnp, Config *const config, bool const first, int64_t const blockbeg)
{
  int64_t total = 0;
  if (!complete_copy(txnp, total)) {
    return false;
  }

  TxnHdrMgr req;
  if (!req.populateFrom(txnp, TSHttpTxnClientReqGet)) {
    return false;
  }
  HttpHeader request(req.m_buffer, req.m_lochdr);

  std::string range;
  if (first) {
    char clientstr[1024];
    range = client_range_of(request, config, clientstr, sizeof(clientstr));
    if (range.empty()) {
      DEBUG_LOG("Serving the whole object from the complete copy");
      return true;
    }
  } else {
    char rangestr[64];
    int  rangelen = sizeof(rangestr);
    if (!Range(blockbeg, blockbeg + config->m_blockbytes).toStringClosed(rangestr, &rangelen)) {
      return false;
    }
    range.assign(rangestr, rangelen);
  }

  Range want;
  if (!want.fromStringClosed(range.c_str())) {
    return false;
  }
  int64_t const beg = want.isEndBytes() ? std::max<int64_t>(0, total + want.m_beg) : want.m_beg;
  if (total <= beg) {
    DEBUG_LOG("%s starts past the end of the complete copy", range.c_str());
    return false;
  }
  DEBUG_LOG("Serving %s from the complete copy", range.c_str());
  // Core serves ranges only to HTTP/1.1 requests. It reads a copy that another transaction still writes only as far as
  // it is written, and with read_while_writer 2 sends a range past that to the origin, uncached.
  TSMgmtInt rww = 0;
  if (TS_HTTP_VERSION(1, 1) == request.version() &&
      (TS_SUCCESS != TSHttpTxnInfoIntGet(txnp, TS_TXN_INFO_CACHE_HIT_RWW, &rww) || 0 == rww)) {
    return request.setKeyVal(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE, range.data(), range.size());
  }
  return serve_window_from_copy(txnp, config, want, total, range);
}

void
on_block_lookup(TSHttpTxn txnp, TSCont contp, Config *const config)
{
  int status = 0;
  if (TS_SUCCESS != TSHttpTxnCacheLookupStatusGet(txnp, &status)) {
    return;
  }
  bool const first = has_mark(txnp, &first_block_mark);

  // The second lookup found an object under the URL's own key. Unless it is a complete copy that holds the request's
  // range, the block request continues as the miss of its own block, with the hook that the miss added.
  intptr_t const relookup =
    0 <= slice_relookup_arg_idx ? reinterpret_cast<intptr_t>(TSUserArgGet(txnp, slice_relookup_arg_idx)) : 0;
  if (0 < relookup) {
    TSUserArgSet(txnp, slice_relookup_arg_idx, nullptr);
    if (TS_CACHE_LOOKUP_HIT_FRESH != status || !serve_from_copy(txnp, config, first, relookup - 1)) {
      DEBUG_LOG("No complete copy under the URL's own key");
      TSHttpTxnCacheLookupStatusSet(txnp, TS_CACHE_LOOKUP_MISS);
    }
    return;
  }

  if (TS_CACHE_LOOKUP_MISS == status || TS_CACHE_LOOKUP_SKIPPED == status) {
    TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
    int64_t blockbeg = 0;
    if (TS_CACHE_LOOKUP_MISS == status && 0 <= slice_relookup_arg_idx && look_up_url_key(txnp, config, blockbeg)) {
      TSUserArgSet(txnp, slice_relookup_arg_idx, reinterpret_cast<void *>(static_cast<intptr_t>(blockbeg + 1)));
    }
  } else if (first && TS_CACHE_LOOKUP_HIT_FRESH == status && serve_from_copy(txnp, config, true, 0)) {
    // A complete copy stored under the block's own key.
    TSHttpTxnHookAdd(txnp, TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
  }
}

void
on_block_response(TSHttpTxn txnp, Config const *const config)
{
  bool const first = has_mark(txnp, &first_block_mark);
  note_block_answer(txnp, config);
  if (!first) {
    return;
  }

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
  if (TS_SUCCESS !=
      TSUserArgIndexReserve(TS_USER_ARGS_TXN, SLICE_RELOOKUP_ARG, "slice block lookup of the URL's key", &slice_relookup_arg_idx)) {
    ERROR_LOG("Failed to reserve the %s transaction argument", SLICE_RELOOKUP_ARG);
  }
}

void
mark_slice_block(TSHttpTxn txnp)
{
  set_mark(txnp, &block_mark);
}

bool
url_key_of_block(TSHttpTxn txnp, Config const *const config, std::string &key, int64_t &blockbeg)
{
  if (!lookup_url_string(txnp, key)) {
    return false;
  }
  constexpr std::string_view bytes = "bytes=";
  constexpr std::string_view range = "Range:";
  for (size_t pos = key.rfind(bytes); std::string::npos != pos; pos = 0 == pos ? std::string::npos : key.rfind(bytes, pos - 1)) {
    size_t len = 0;
    if (!parse_block_range(std::string_view{key}.substr(pos), config->m_blockbytes, blockbeg, len)) {
      continue;
    }
    size_t const end = pos + len;
    // cache_range_requests: <URL>-<Range>
    if (end == key.size() && 0 < pos && '-' == key[pos - 1]) {
      key.resize(pos - 1);
      return true;
    }
    // cachekey: <separator>Range:<Range>, then the next element or the end
    if (range.size() < pos && 0 == strncasecmp(key.data() + pos - range.size(), range.data(), range.size())) {
      size_t const beg = pos - range.size() - 1;
      key.erase(beg, end - beg);
      return true;
    }
  }
  return false;
}

bool
look_up_url_key(TSHttpTxn txnp, Config const *const config, int64_t &blockbeg)
{
  std::string key;
  if (!url_key_of_block(txnp, config, key, blockbeg) || TS_SUCCESS != TSHttpTxnCacheLookupAgain(txnp, key.data(), key.size())) {
    return false;
  }
  DEBUG_LOG("Block at %" PRId64 " is not cached, looking up the URL's own key: %s", blockbeg, key.c_str());
  return true;
}

void
note_block_answer(TSHttpTxn txnp, Config const *const config)
{
  TxnHdrMgr req;
  TxnHdrMgr resp;
  if (!req.populateFrom(txnp, TSHttpTxnServerReqGet) || !resp.populateFrom(txnp, TSHttpTxnServerRespGet)) {
    return;
  }
  HttpHeader const request(req.m_buffer, req.m_lochdr);
  HttpHeader const response(resp.m_buffer, resp.m_lochdr);
  if (!request.hasKey(TS_MIME_FIELD_RANGE, TS_MIME_LEN_RANGE) || TS_HTTP_STATUS_OK != response.status() ||
      response.hasKey(TS_MIME_FIELD_CONTENT_RANGE, TS_MIME_LEN_CONTENT_RANGE)) {
    return;
  }

  std::string key;
  int64_t     blockbeg = 0;
  if (url_key_of_block(txnp, config, key, blockbeg) && TS_SUCCESS == TSHttpTxnCacheWriteUrlSet(txnp, key.data(), key.size())) {
    DEBUG_LOG("Upstream sent the whole object for the block at %" PRId64 ", storing it under the URL's own key", blockbeg);
    set_mark(txnp, &whole_mark);
  }
}

void
watch_block_request(TSHttpTxn txnp, HttpHeader &header, TSCont contp)
{
  if (TS_HTTP_METHOD_GET != header.method()) {
    return;
  }
  if (header.hasKey(SLICE_FIRST_BLOCK_HEADER.data(), SLICE_FIRST_BLOCK_HEADER.size())) {
    header.removeKey(SLICE_FIRST_BLOCK_HEADER.data(), SLICE_FIRST_BLOCK_HEADER.size());
    set_mark(txnp, &first_block_mark);
  } else {
    mark_slice_block(txnp);
  }
  TSHttpTxnHookAdd(txnp, TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, contp);
}

int
block_handler(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn const txnp   = static_cast<TSHttpTxn>(edata);
  Config *const   config = static_cast<Config *>(TSContDataGet(contp));

  switch (event) {
  case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
    on_block_lookup(txnp, contp, config);
    break;
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    on_block_response(txnp, config);
    break;
  default:
    break;
  }

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
  return 0;
}
