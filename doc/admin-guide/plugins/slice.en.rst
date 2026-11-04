.. Licensed to the Apache Software Foundation (ASF) under one
   or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.

.. include:: ../../common.defs

.. _admin-plugins-slice:

Slice Plugin
***************

This plugin takes client requests and breaks them up into
successive aligned block requests.  This supports both
whole asset and single range requests.

Purpose
=======

This slice plugin, along with the `cache_range_requests`
plugin allows the following:

-  Fulfill arbitrary range requests by fetching a minimum
   number of cacheable aligned blocks to fulfill the request.
-  Breaks up very large assets into much smaller cache
   blocks that can be spread across multiple storage
   devices and within cache groups.

How It Works
============

The `slice` plugin takes GET requests and breaks them into
successive aligned range requested blocks.  It issues these
range requests back into the ATS instance and relies on the
`cache_range_requests` plugin to interact with the caching layer.

This design was chosen because the `cache_range_requests`
plugin was already proven to work well with the ATS caching layer.
The `slice` plugin has the already difficult task of managing
multiple block requests and all of the associated flow control
between the cache_range_requests plugin and the downstream clients.

Configuration
=============

This plugin is intended for use as a remap plugin and is
configured in :file:`remap.config`.

Or preferably per remap rule in :file:`remap.config`::

    map http://ats/ http://parent/ @plugin=slice.so \
        @plugin=cache_range_requests.so

In this case, the plugin will use the default behaviour:

-  Fulfill whole file or range requests by requesting cacheable
   block aligned ranges from the parent and assemble them
   into client responses, either 200 or 206 depending on the
   client request.
-  Default block size is 1mb (1048576 bytes).
-  This plugin depends on the cache_range_requests plugin
   to perform actual parent fetching and block caching
   and If-* conditional header evaluations.

Plugin Options
--------------

The slice plugin supports the following options::

    --blockbytes=<bytes> (optional)
        Default is 1m or 1048576 bytes
        -b <bytes> for short.
        Suffix k,m,g supported
        Limited to 32k and 128m inclusive.

    --blockbytes-test=<bytes> (optional)
        Suffix k,m,g supported
        -t <bytes> for short.
        Limited to any positive number.
        Ignored if --blockbytes provided.

    --disable-errorlog (optional)
        Disable writing block stitch errors to the error log.
        -d for short

    --exclude-regex=<regex> (optional)
        If provided, only slice what matches.
        If not provided will always slice
        Cannot be used with --include-regex
        -e for short

    --include-regex=<regex> (optional)
        If provided, only slice what matches.
        If not provided will always slice
        Cannot be used with --exclude-regex
        -i for short

    --pace-errorlog=<seconds> (optional)
        Limit stitching error logs to every 'n' second(s)
        -p for short

    --ref-relative (optional)
        Self healing mode typically uses slice 0 as the reference slice
        for every request.  This is very safe but also increases plugin
        time and latency as the first slice is always fully processed
        whether or not the original requests needs any data from slice 0.
        This option uses the first slice in the request as reference
        which has better performance.  A downside of this mode is that
        self healing won't happen if blocks in a request agree.
        Normally leave this off.
        -l for short

    --remap-host=<loopback hostname> (optional)
        Uses effective url with given hostname for remapping.
        Requires setting up an intermediate loopback remap rule.
        -r for short

    --skip-header=<header name> (default: X-Slicer-Info)
        Header name used by the slice plugin after the loopback
        to indicate that the slice plugin should be skipped.
        Slice's own block requests always have a Range, so a GET that has
        this header but no Range is sliced: it is a copy of a block request
        that another plugin made for the whole object, as the prefetch
        plugin does for the next objects.  Slicing it stores the object as
        the blocks that later requests look up.
        -s for short

    --crr-ident-header=<header name> (default: X-Crr-Ident)
        Header name used by the slice plugin to tell the
        `cache_range_requests` plugin the identifier of the
        first/reference slice fetched.  First Etag is preferred
        followed by Last-Modified. The `cache_range_requests`
				plugin uses this header to flip cache lookup status
				to STALE or FRESH depending on the header.

    --prefetch-count=<int> (optional)
        Default is 0
        Prefetches successive 'n' slice block requests in the background
        and caches (with `cache_range_requests` plugin). Prefetching is only
        enabled when first block (of the client request) is a cacheable object
        with miss or hit-stale status. Especially for large objects, prefetching
        can improve cache miss latency.
        -f for short

    --strip-range-for-head (optional)
        Enable slice plugin to strip Range header for HEAD requests.
        -h for short

    --minimum-size (optional)
    --metadata-cache-size (optional)
    --stats-prefix (optional)
        In combination, these three options allow for conditional slice.
        Specify the minimum size object to slice with --minimum-size.  Allowed
        values are the same as --blockbytes.  Conditional slicing uses a cache
        of object sizes to make the decision of whether to slice.  The cache
        will only store the URL of large objects as they are discovered in
        origin responses.  You should set the --metadata-cache-size to by
        estimating the working set size of large objects.  You can use
        stats to determine whether --metadata-cache-size was set optimally.
        Stat names are prefixed with the value of --stats-prefix.  The names
        are:

        <prefix>.metadata_cache.true_large_objects - large object cache hits
        <prefix>.metadata_cache.true_small_objects - small object cache hits
        <prefix>.metadata_cache.false_large_objects - large object cache misses
        <prefix>.metadata_cache.false_small_objects - small object cache misses
        <prefix>.metadata_cache.no_content_length - number of responses without content length
        <prefix>.metadata_cache.bad_content_length - number of responses with invalid content length
        <prefix>.metadata_cache.no_url - number of responses where URL parsing failed

        If an object size is not found in the object size cache, the plugin
        will not slice the object, and will turn off ATS cache on this request.
        The object size will be cached in following requests, and slice will
        proceed normally if the object meets the minimum size requirement.

        Range requests from the client for small objects are passed through the
        plugin unchanged.  If you use the `cache_range_requests` plugin, slice plugin
        will communicate with `cache_range_requests` using an internal header
        that causes `cache_range_requests` to be bypassed in such requests, and
        allow ATS to handle those range requests internally.

    --inline-first-block (optional)
        Serve a GET in the client's own transaction instead of intercepting
        it.  Slice turns the request into the request for the block that holds
        the first byte the client asked for (block 0 for a whole-object GET),
        as it would send that block itself, and the rest of the remap chain
        handles it like a block request.  The decision waits for the response:

        - A block that already is the client's response (the whole object, or
          exactly the requested range) is sent as a 200 or a 206.  It takes
          one transaction and is stored as that block.
        - Otherwise slice sends the client's part of the block, followed by
          the rest of the requested bytes, which it requests block by block in
          the client's transaction, without an intercept.  As when slicing,
          these block requests carry the first block's identity,
          ``--prefetch-count`` applies when the first block missed, and a
          block from a newer version of the object ends the response and
          requests block 0 again so that the next request is consistent.
        - On a fresh cache hit, a range that lies inside one block is served
          by ATS's own range support, which reads only the requested bytes
          from the cache, unless another transaction is still writing the
          block; then slice cuts the range out of the block as it arrives.
          If the range ends inside a later block that is already cached,
          slice stops reading that block at the end of the range.
        - A range that starts at or past the end of the object gets a 416.
        - A 200 from an origin that ignores Range reaches the client unchanged
          (see "Origins That Ignore Range" below).
        - A 416 for a zero-length object becomes an empty 200.
        - A 206 without a usable Content-Range becomes a 502.
        - Other statuses reach the client unchanged.

        The decision follows the response that ATS actually serves, so a stale
        block that ATS serves because revalidation failed is handled like a
        fresh one.  A partial block is never sent as if it were the client's
        whole response: if the rest cannot follow, the connection is closed.

        As when slicing, each block is read as fast as it arrives, and the
        next block is requested only while at most one block waits for the
        client, so a slow client holds about two blocks.  If the client
        aborts while the first block arrives, the cache write of that block
        continues as a background fill, subject to
        :ts:cv:`proxy.config.http.background_fill_completed_threshold`.

        Suffix ranges (``bytes=-n``), multiple ranges, invalid ranges, HEAD,
        PURGE and conditional requests are sliced as usual.  The rule must
        include `cache_range_requests` after slice.  With
        --metadata-cache-size, slice also remembers URLs found to be larger
        than one block and slices whole-object GETs for them directly.

        The first block is the client's own transaction, with the block's
        Range, until `cache_range_requests` removes it.  `background_fetch`
        recognizes it as one of slice's block requests and does not fetch
        the whole object for it, wherever it runs.

    --purge-probe-blocks=<int> (optional)
        Default is 8
        How many consecutive uncached slice blocks a PURGE walks, before any block
        has reported the object's extent, until it concludes that nothing about the
        object is cached.  May be overridden per request with the header named by
        ``--purge-probe-header``.  See `Purge Requests`_.
        -q for short

    --purge-probe-header=<string> (optional)
        Default is X-Slice-Purge-Probe
        Name of the request header a PURGE may use to override
        ``--purge-probe-blocks`` for that request.  A malformed value is ignored
        in favour of the configured default.  Slice strips this header from the
        block requests it issues.
        -H for short

Examples::

    @plugin=slice.so @pparam=--blockbytes=1000000 @plugin=cache_range_requests.so

Or alternatively::

    @plugin=slice.so @pparam=-b @pparam=1000000 @plugin=cache_range_requests.so

Byte suffix examples::

    slice.so --blockbytes=5m
    slice.so -b 512k
    slice.so --blockbytes=32m

For testing and extreme purposes the parameter ``blockbytes-test`` may
be used instead which is unchecked::

    slice.so --blockbytes-test=1G
    slice.so -t 13

Because the slice plugin is susceptible to errors during block stitching
extra logs related to stitching are written to ``diags.log``.  Worst case
an error log entry could be generated for every transaction.  The
following options are provided to help with log overrun::

    slice.so --pace-errorlog=5
    slice.so -p 1
    slice.so --disable-errorlog

After modifying :file:`remap.config`, restart or reload |TS|
(sudo traffic_ctl config reload) or (sudo traffic_ctl server restart)
to activate the new configuration values.

Don't slice txt files::

  slice.so --exclude-regex=\\.txt
  slice.so -e \\.txt

Slice only mp4 files::

  slice.so --include-regex=\\.mp4
  slice.so -i \\.mp4

Debug Options
-------------

While the current slice plugin is able to detect block consistency
errors during the block stitching process, it can only abort the
client connection.  A CDN can only "fix" these by issuing an appropriate
content revalidation.

Under normal logging these slice block errors tend to show up as::

    pscl value 0
    crc value ERR_READ_ERROR

By default more detailed stitching errors are written to ``diags.log``.

.. topic:: Example

    ERROR: [slice.cc: 288] logSliceError(): 1555705573.639 reason="Non 206 internal block response" uri="http://ats_ep/someasset.mp4" uas="curl" req_range="bytes=1000000-" norm_range="bytes 1000000-52428799/52428800" etag_exp="%221603934496%22" lm_exp="Fri, 19 Apr 2019 18:53:20 GMT" blk_range="21000000-21999999" status_got="206" cr_got="" etag_got="%221603934496%22" lm_got="" cc="no-store" via=""

    ERROR: [server.cc: 288] logSliceError(): 1572370000.219 reason="Mismatch block Etag" uri="http://ats_ep/someasset.mp4" uas="curl" req_range="bytes=1092779033-1096299354" norm_range="bytes 1092779033-1096299354/2147483648" etag_exp="%223719843648%22" lm_exp="Tue, 29 Oct 2019 14:40:00 GMT" blk_range="1095000000-1095999999" status_got="206" cr_got="bytes 1095000000-1095999999/2147483648" etag_got="%223719853648%22" lm_got="Tue, 29 Oct 2019 17:26:40 GMT" cc="max-age=10000" via=""

Whether or how often these detailed log entries are written are
configurable plugin options.

Implementation Notes
====================

This slice plugin is a stop gap plugin for handling special cases
involving very large assets that may be range requested. Hopefully
the slice plugin is deprecated in the future when partial object
caching is finally implemented.

Slice *ONLY* handles slicing up requests into blocks, it delegates
actual caching and fetching to the cache_range_requests.so plugin.

Plugin Function
---------------

Below is a quick functional outline of how a request is served
by a remap rule containing the Slice plugin with cache_range_requests:

For each client request that comes in all remap plugins are run up
until the slice plugin is hit.  If the slice plugin *can* be run (ie:
GET request) it will handle the request and STOP any further plugins
from executing.

At this point the request is sliced into 1 or more blocks by
adding in range request headers ("Range: bytes=").  A special
header X-Slicer-Info header is added and the pristine URL is
restored.

For each of these blocks separate sequential TSHttpConnect(s) are
made back into the front end of ATS.  By default of the remap plugins
are rerun.  Slice skips the remap due to presence of the X-Slicer-Info
header and allows cache_range_requests.so to serve the slice block back
to Slice either via cache OR parent request.

Slice assembles a header based on the very first slice block response
and sends it to the client.  If necessary it then skips over bytes in the
first block and starts sending byte content, examining each block header
and sends its bytes to the client until the client request is satisfied.

Any extra bytes at the end of the last block are consumed by the
Slice plugin to allow cache_range_requests to finish the block fetch to
ensure the block is cached.

Self Healing
------------

The slice plugin uses the very first slice as a reference slice which
uses content-length and etag or last-modified headers to ensure assembled
blocks come from the same asset.  In the case where a slice from a parent
is fetched which indicates that the asset has changed, the slice plugin
will attempt to self heal the asset.  The `cache_range_requests` plugin
must be configured with the `--consider-ident` parameter in order for
this to work.

Example `remap.config` configuration::

  map http://slice/ http://parent/ @plugin=slice.so @pparam=--remap-host=cache_range_requests
  map http://cache_range_requests/ http://parent/ @plugin=cache_range_requests.so @pparam=--consider-ident

When a request is served, the slice plugin uses the header from slice 0
requested range build a response to the client. When subsequent slices
are requested from the parent the X-Crr-Ident header is populated with
the reference identifier (etag or last-modified) and the request is made
through the `cache_range_requests` plugin.  The `cache_range_requests`
plugin will then decide whether to send back the current cached slice
(if the identifier matches) or attempt to refetch or "heal" that slice
by marking it STALE.

If the slice returned by the cache_range_requests plugin still
doesn't match the reference slice then client side of the transaction
is aborted.  The plugin will then attempt to "heal" the reference
slice.  The X-Crr-Ident header is populated with the new identifer
and the reference slice is re-requested with the intent of having the
`cache_range_requests` plugin "heal" the reference slice.

The plugin may be configured to use the first slice of the request
as the reference slice instead of the asset slice 0.  This option is
faster as it does not visit any slices outside those needed to fulfill
a request. This option may cause serious out of sync issues as range
requests may end up being served from temporally different assets.

Blocks That Are Not Stored
--------------------------

When the transaction for a block will not store it, for example because
:ref:`admin-plugins-cache-promote` has not promoted the object yet,
`cache_range_requests` asks upstream for less than the block.  For the first
block of a client request it asks for the client's own request: the client's
range, or the whole object without a Range for a whole-object GET, and the
response reaches the client unchanged.  For a later block it asks for the part
of the block that the client needs.  So a request that is not stored costs
upstream no more than it would without slice.  Slice removes its own headers
from such a request, so an upstream proxy that runs slice treats it as an
ordinary client request, not as one of slice's block requests.  cache_promote
counts slice's block requests per object.

Concurrent Requests for a Block
-------------------------------

Concurrent requests for the same uncached block all miss in the cache until the
first of them opens the block's cache write.  Slice's block requests share the
block's cache key, so the others can read the block from that writer, but only
when the rule allows read retries.  Otherwise each of them fetches the whole
block from the origin again, without caching it.  Set
:ts:cv:`proxy.config.http.cache.open_write_fail_action` to ``6`` (or ``5``) and
:ts:cv:`proxy.config.http.cache.max_open_read_retries` above ``0`` with
:ref:`admin-plugins-conf-remap` on the sliced rule, and also on the loopback rule
with ``--remap-host``.

Origins That Ignore Range
-------------------------

An upstream that ignores Range answers a block request with a 200 for the
whole object.  The client gets that 200, as it would without slice.  Slice
stores the response once, under the URL's own key: the key that the same
request has without slice and `cache_range_requests`.  It moves the block
request's cache write there when the response arrives, whichever block the
request was for.

Every block request that misses in the cache looks up the URL's own key once
more.  A fresh complete copy there (a 200 without Content-Range) serves the
request: the client's range as a 206, the whole object for a whole-object GET,
or the block for a later block.  When another request is still writing the
copy, or the client uses HTTP/1.0, slice cuts the range out of the copy as it
arrives.  A range that starts at or past the end of the copy goes upstream.  So the object is fetched once, whichever range comes
first, and a complete copy that a request without slice stored serves sliced
requests too.  For an upstream that honors Range the URL's own key holds
nothing, and the second lookup finds nothing in the cache directory.  A stale
copy is not revalidated: the block request goes upstream, and a new
whole-object answer replaces the copy.

Slice finds the URL's own key by removing the block's Range from the block's
cache key: the ``-<Range>`` that `cache_range_requests` appends to the URL, or
the ``Range:<Range>`` element, with the separator before it, that
:ref:`admin-plugins-cachekey` adds with ``--include-headers=Range``.  That is
the key of the same request without slice when `cache_range_requests` builds
the key from the URL, and when cachekey runs before `cache_range_requests`
with ``--include-headers=Range`` and its default separator.  It differs when
the block's key holds the Range some other way, for example through
cachekey's ``--capture-header`` or a separator of more than one character:
slice then stores and finds its copy under a key of its own, which requests
without slice do not share.  When a block's key holds no block Range at all,
slice does not move the write or look up again, and `cache_range_requests`
stores a complete response only for the request for block 0, under that
block's key.  With ``--remap-host`` the block requests go through a rule
without slice, which does neither.

Purge Requests
--------------

The slice plugin supports PURGE requests, discarding the requested object from
cache. Without a range every block is discarded; with a range, the blocks that
range covers are. Two cases below purge more than the range names: a suffix range,
and block 0 when ``--ref-relative`` is disabled.

Slice issues one PURGE per block and walks every block it was asked for, whether
or not each one is currently cached. A block that is already absent answers 404
internally; that is simply noted and the walk continues, so a gap left by
per-block eviction cannot leave the blocks behind it in cache.

Slice learns where the object ends from the blocks it removes. PURGE is a Traffic
Server extension, so a successful block purge reports the removed object's extent
in a ``X-Purged-Content-Range`` header, and the walk continues to the last block that
extent implies. Blocks of one object can disagree about its length when the origin
object has been replaced in place; slice takes the largest extent any block
reports, so the longer generation's tail is not left behind.

Until some block has reported an extent, a walk over an open-ended range has no
end but the miss bound: it stops after ``--purge-probe-blocks`` consecutive
uncached blocks and reports that nothing was found. That is what bounds a PURGE
for a URL which is not cached at all.

An operator often knows more about the object than the plugin does, since the
block count is just the object's size divided by the block size. That count can be
supplied per request with the header named by ``--purge-probe-header``, default
``X-Slice-Purge-Probe``::

    PURGE /obj HTTP/1.1
    X-Slice-Purge-Probe: 64

This only changes how long the walk keeps going without having found anything; it
never limits how many blocks are purged once an extent is known.

The bound has to be able to span a whole object, because in the worst case only
the object's last block is still cached, so the value an operator wants is the
object's size divided by the block size: a 10 GB object in 1 MB blocks needs
10240. There is no ceiling on it beyond that, since reaching the bound costs one
internal cache lookup per block and PURGE is already restricted by
:file:`ip_allow.yaml`. A malformed value is ignored in favour of the configured
default, and slice strips the header from the block requests it issues.

If the bound is reached, slice logs that it gave up and reports ``404`` even though
later blocks may still be cached. Raise ``--purge-probe-blocks``, or send the
override, for objects whose leading blocks are routinely absent.

A client range that is already closed, such as ``bytes=0-6399999999``, bounds the
walk directly, and is clamped against the object's extent as soon as some block
reports one. An over-estimate therefore costs no extra block PURGEs beyond the end
of the object, and if no block is cached at all the miss bound stops the walk.

A suffix range, ``bytes=-<n>``, names its blocks by their distance from an end
slice does not know yet, and purging is the only way it could find out. Rather
than guess at the start, such a purge is widened to the whole object: a superset of
what was asked for, so the named blocks certainly go. A ``GET`` with the same header
is unaffected and still returns exactly the last *n* bytes.

After the blocks, slice sends one PURGE without a Range, which removes a complete
copy stored under the URL's own key (see "Origins That Ignore Range" above).

The response is sent once the walk is complete: ``200`` if at least one block, or
the complete copy, was removed, ``404`` if none was found. This matches what
Traffic Server reports for a PURGE of an object that is not sliced.

A block whose PURGE returns neither ``200`` nor ``404`` — a ``403`` from
:file:`ip_allow.yaml`, for instance, or a ``502`` — says nothing about whether that
block was cached, and nothing about the blocks behind it. The walk stops there and that
status is reported in place of ``200``, so the two success statuses keep meaning what
they say: ``200`` that the object is gone and ``404`` that it was not there, never that
this proxy could not tell. Blocks the walk had already removed stay removed, and blocks
behind the failing one are left cached, so such a PURGE is worth repeating once
whatever refused it has been dealt with.

The functionality works with ``--ref-relative`` both enabled and disabled. With it
disabled, block 0 is always the first block walked, so a PURGE whose range does not
cover block 0 still purges it.

Conditional Slicing
-------------------

The goal of conditional slicing is to slice large objects and avoid the cost of slicing on small
objects.  If `--minimum-size` is specified, conditional slicing is enabled and works as follows.

The plugin builds a object size cache in memory.  The key is the URL of the object.  Only
large object URLs are written to the cache.  The object size cache uses CLOCK eviction algorithm
in order to have lazy promotion behavior.

When a URL not found in the object size cache, the plugin treats the object as a small object.  It
will not intercept the request.  The request is processed by ATS without any slice logic.  Upon
receiving a response, the slice plugin will check the response content length to update the object
size cache if necessary.

When a large URL is requested for the first time, conditional slicing will not intercept that
request since the URL is not known to be large.  This will cause an ATS cache miss and the request
will go to origin server.  Slice plugin will turn off writing to cache for this response, because
it expects to slice this object in future requests.

If the object size cache evicts a URL, the size of the object for that URL will need to be learned
again in a subsequent request, and the behavior above will happen again.

If the URL is found in the object size cache, conditional slicing treats the object as a large object
and will activate the slicing logic as described in the rest of this document.

If the client sends a range request, and that URL is not in the object size cache, the slice plugin
will forward the range request to ATS core.  It also attaches an internal header in order to deactivate
the `cache_range_requests` plugin for this range request.

Important Notes
===============

This plugin assumes that the content requested is cacheable.

Any first block server response that is not a 206 is passed directly
down to the client. Any 200 responses are passed back through to
the client.

Only the first server response block is used to evaluate any "If-"
conditional headers.  Subsequent server slice block requests
remove these headers.

The only 416 response that this plugin handles itself is if the
requested range is inside the last slice block but past the end of
the asset contents.  Other 416 responses are handled by the parent.

If a client aborts mid transaction the current slice block continues to
be read from the server until it is complete to ensure that the block
is cached.

Slice *always* makes ``blockbytes`` sized requests which are handled
by cache_range_requests.  The parent will trim those requests to
account for the asset Content-Length so only the appropriate number
of bytes are actually transferred and cached.

Effective URL remap
===================

By default the plugin restores the Pristine Url which reuses the same
remap rule for each slice block.  This is wasteful in that it reruns
the previous remap rules, and those remap rules must be smart enough to
check for the existence of any headers they may have created the first
time they have were visited.

To get around this the '--remap-host=<host>' or '-r <host>' option may
be used.  This requires an intermediate loopback remap to be defined which
handles each slice block request.

This works well with any remap rules that use the url_sig or uri_signing
plugins.  As the client remap rule is not caching any plugins that
manipulate the cache key would need to go into the loopback to parent
remap rule.

NOTE: Requests NOT handled by the slice plugin (ie: HEAD requests) are
handled as with a typical remap rule.  GET requests intercepted by the
slice plugin are virtually reissued into ATS and are proxied through
another remap rule which must contain the ``cache_range_requests`` plugin

Examples::

    map http://ats/ http://parent/ @plugin=slice.so @pparam=--remap-host=loopback
    map http://loopback/ http://parent/ @plugin=cache_range_requests.so

Alternatively::

    map http://ats/ http://parent/ @plugin=slice.so @pparam=-r @pparam=loopback
    map http://loopback/ http://parent/ @plugin=cache_range_requests.so

Current Limitations
===================

Since the Slice plugin is written as an intercept handler it loses the
ability to use normal state machine hooks and transaction states. This
functionality is handled by using the ``cache_range_requests`` plugin
to interact with ATS.
