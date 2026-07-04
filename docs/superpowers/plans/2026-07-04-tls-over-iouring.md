# TLS over io_uring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** TLS traffic (inbound termination + outbound origin) runs over the io_uring coroutine transport on branch `io-uring-tls-wip`, validated by the TLS gold suite, then measured against TLS-over-epoll.

**Architecture:** Merge `tls-refactor-wip` (layered `SSLNetVConnection` over an inner `UnixNetVConnection*`) into the io_uring branch. `IOUringNetVConnection` *is a* `UnixNetVConnection`, so once `SSLNetProcessor::createNetAccept` follows the `proxy.config.net.io_uring.enabled` gate, the accept path hands the SSL layer an io_uring inner VC and the layering works by contract. Outbound already routes through the gated `UnixNetProcessor::allocate_vc`. One small correctness fix (`reenable_re`) plus verify-only friction checks.

**Tech Stack:** C++20 (coroutines), liburing, CMake presets (`claude-dev`, `claude-dev-asan` in `CMakeUserPresets.json`), autest gold tests, OpenSSL.

**Spec:** `docs/superpowers/specs/2026-07-04-tls-over-iouring-design.md`

## Global Constraints

- Work in `/home/mo/work/trafficserver-io-uring` on branch `io-uring-tls-wip`. Never commit to `io-uring-coroutine-wip` or `tls-refactor-wip`.
- Full build before install; never gate a build behind a pipe (masks the return code). Autests run the **installed** tree: `cmake --install <builddir>` after every build or the test silently uses a stale binary.
- `claude-dev` preset → `build-dev/`, installs to `/tmp/ats-dev`. `claude-dev-asan` → `build-dev-asan/`, installs to `/tmp/ats-dev-asan`.
- Run autest suites serially. If two `autest.sh` runs must overlap, give each a distinct `AUTEST_PORT_OFFSET` (0, 1000, …) or they deterministically collide.
- A "flaky" SEGV under concurrent autests is a known port-collision artifact — rerun solo before believing it.
- The TLS gold suite lives in `tests/gold_tests/tls/` (69 test files post-merge); the io_uring suite in `tests/gold_tests/io_uring/` (21 files, each sets `proxy.config.net.io_uring.enabled: 1` itself).
- Commit messages: state the change and its motivation only; no meta-commentary, no attribution trailers.
- Pushing `io-uring-tls-wip` to the `moonchen` fork is pre-authorized; do not push to `origin` (apache) or open PRs.

---

### Task 1: Merge `tls-refactor-wip` into `io-uring-tls-wip`

**Files:**
- Modify: merge across the tree. Conflicts expected in (union of both feature diffs vs the common base `b13b9858ac`): `src/iocore/net/UnixNetAccept.cc`, `src/iocore/net/UnixNetProcessor.cc`, `src/iocore/net/UnixNet.cc`, `src/iocore/net/NetHandler.cc` (if split differs), `src/iocore/net/CMakeLists.txt`, `src/records/RecordsConfig.cc`, `include/iocore/eventsystem/IOBuffer.h`, `src/iocore/cache/CacheVC.cc`, `src/proxy/http/HttpConfig.cc`, `src/traffic_crashlog/traffic_crashlog.cc`, `src/traffic_layout/info.cc`, `doc/developer-guide/index.en.rst`, `tests/README.md`.

**Interfaces:**
- Consumes: local branch `tls-refactor-wip` @ `d271d16c36` (verified identical to the sibling tree and the moonchen fork).
- Produces: a building merged tree where later tasks find: `IOUringNetVConnection`/`IOUringNetAccept` intact; refactored `SSLNetVConnection : public NetVConnection` with `UnixNetVConnection *_unvc`; `UnixNetProcessor::allocate_vc` io_uring gate intact; `net_io_uring_enabled()` file-static in `UnixNetProcessor.cc`.

- [ ] **Step 1: Preflight**

```bash
cd /home/mo/work/trafficserver-io-uring
git status --short          # expect: clean
git branch --show-current   # expect: io-uring-tls-wip
git rev-parse tls-refactor-wip   # expect: d271d16c36a040fdf9d283bf449756de60bc28bb
```

- [ ] **Step 2: Merge**

```bash
git merge tls-refactor-wip
```

Expected: conflict list roughly matching the Files section. `git status` shows `both modified` entries.

- [ ] **Step 3: Resolve conflicts**

Resolution principles per file class:

| File | Rule |
|---|---|
| `UnixNetAccept.cc` | Take the TLS side for shared accept code (its accept sites allocate the inner VC via `unix_netProcessor.allocate_vc(...)` at ~:135/:420/:590 — that convention must survive). Keep the whole io_uring side's `IOUringNetAccept` implementation block (at file bottom, `#if TS_USE_LINUX_IO_URING`, ~lines 694–838 pre-merge) and its `#include "P_IOUringNetAccept.h"`. |
| `UnixNetProcessor.cc` | Keep all four io_uring insertions applied onto the TLS-side base: (1) includes + `static net_io_uring_enabled()` (pre-merge :30–41), (2) per-thread accept forcing in `accept_internal` (:152–158), (3) `createNetAccept` gate returning `IOUringNetAccept` (:321–326), (4) `allocate_vc` gate returning `ioUringNetVCAllocator.alloc()` (:329–350). |
| `UnixNet.cc` / `NetHandler.cc` | Keep the io_uring branch's `waitForActivity` ring branch (+ poll bridge) on the TLS-side base. |
| `CMakeLists.txt`, `RecordsConfig.cc`, `index.en.rst`, `tests/README.md` | Union — both sides added entries; keep both. |
| `IOBuffer.h`, `CacheVC.cc`, `HttpConfig.cc`, `traffic_crashlog.cc`, `info.cc` | io_uring-side edits vs unrelated master-delta edits: apply both semantically. For `HttpConfig.cc` specifically, the io_uring startup `Fatal()` for `server_session_sharing.pool != thread` (pre-merge :857–869) must survive. |

Special checks while resolving:
- If the base still declares `UnixNetVConnection::_isReadyToTransferData` and the TLS side removed it, drop the io_uring write-drive's call to it (`IOUringNetVConnection.cc` `_write`, pre-merge ~:1304); if the virtual still exists, leave the call alone.
- `accept_internal`'s `na->snpa = dynamic_cast<SSLNextProtocolAccept *>(cont)` line: keep whatever shape the TLS side has for SNPA handling; only ensure the io_uring per-thread forcing sits alongside it.

- [ ] **Step 4: Semantic post-checks**

```bash
grep -n "class SSLNetVConnection : public NetVConnection" src/iocore/net/P_SSLNetVConnection.h   # refactored SSL VC won
grep -n "UnixNetVConnection \*_unvc" src/iocore/net/P_SSLNetVConnection.h                        # inner-VC member present
grep -n "IOUringNetAccept" src/iocore/net/UnixNetAccept.cc | head -3                             # io_uring accept survived
grep -n "net_io_uring_enabled" src/iocore/net/UnixNetProcessor.cc | head -3                      # gate survived
grep -c "io_uring.enabled" src/records/RecordsConfig.cc                                          # expect 1
grep -rn "unix_netProcessor.allocate_vc" src/iocore/net/UnixNetAccept.cc                         # expect 3 sites
```

- [ ] **Step 5: Build and install**

```bash
cmake --preset claude-dev        # only if build-dev/ is stale/configured against old sources; harmless to re-run
cmake --build build-dev -j"$(nproc)"
cmake --install build-dev
```

Expected: build completes with exit 0. Compile errors here are merge-resolution bugs — fix them in the working tree before committing.

- [ ] **Step 6: Run the C++ unit tests**

```bash
ctest --test-dir build-dev -j"$(nproc)" --output-on-failure
```

Expected: all pass (both branches were green independently; failures indicate a bad resolution).

- [ ] **Step 7: Commit the merge**

```bash
git add -A
git commit   # merge commit; default "Merge branch 'tls-refactor-wip' into io-uring-tls-wip" subject is fine; body: one line on the resolution scope
```

---

### Task 2: Post-merge regression baselines (no code changes)

**Files:** none (test runs only).

**Interfaces:**
- Consumes: `/tmp/ats-dev` install from Task 1.
- Produces: recorded pass/fail baselines that Tasks 3–6 compare against.

- [ ] **Step 1: io_uring suite (transport regression, plain HTTP)**

```bash
cd /home/mo/work/trafficserver-io-uring/tests
./autest.sh --ats-bin /tmp/ats-dev/bin --sandbox /tmp/au-merge-iou -f $(ls gold_tests/io_uring/*.test.py | xargs -n1 basename | sed 's/\.test\.py//')
```

Expected: 21/21 pass. Any failure = merge regression in the io_uring path; debug (superpowers:systematic-debugging) before proceeding.

- [ ] **Step 2: TLS suite at default config (epoll transport — refactor parity)**

```bash
./autest.sh --ats-bin /tmp/ats-dev/bin --sandbox /tmp/au-merge-tls -f $(ls gold_tests/tls/*.test.py | xargs -n1 basename | sed 's/\.test\.py//')
```

Expected: matches the `tls-refactor-wip` tree's own results (historically ~74 pass / 0 fail / small skip count). For any failure, rerun that single test in `/home/mo/work/trafficserver-tls-refactor` against its own build to classify pre-existing vs merge-caused; only merge-caused failures block.

- [ ] **Step 3: Record the two baselines**

Append the counts and any skipped/failing test names to the PR-notes scratch section at the bottom of this plan file (or a `notes.md` next to it). No commit.

---

### Task 3: Route SSL accepts through the io_uring gate

**Files:**
- Modify: `src/iocore/net/P_UnixNetProcessor.h` (declare `net_io_uring_enabled()`)
- Modify: `src/iocore/net/UnixNetProcessor.cc` (un-static it)
- Modify: `src/iocore/net/SSLNetProcessor.cc` (`createNetAccept` gate)
- Create: `tests/gold_tests/io_uring/io_uring_tls.test.py`
- Create: `tests/gold_tests/io_uring/ssl/server.pem`, `tests/gold_tests/io_uring/ssl/server.key` (copied from `tests/gold_tests/tls/ssl/`)

**Interfaces:**
- Consumes: `IOUringNetAccept(const NetProcessor::AcceptOptions &)` (from `P_IOUringNetAccept.h`); its `handle_complete` allocates the inner VC via `this->getNetProcessor()->allocate_vc(t)` where the base `NetAccept::getNetProcessor()` returns `&netProcessor` → the gated Unix allocator. Verified: nothing in the TCP accept path consumes `SSLNetAccept::getNetProcessor()` (only QUIC uses that hook), so substituting a plain `IOUringNetAccept` is safe.
- Produces: `bool net_io_uring_enabled();` visible to net-module code; SSL listen ports arm io_uring accepts when enabled; startup line `io_uring accept enabled for TLS port <n>` in diags.

- [ ] **Step 1: Copy test certs into the io_uring suite dir**

```bash
cd /home/mo/work/trafficserver-io-uring
mkdir -p tests/gold_tests/io_uring/ssl
cp tests/gold_tests/tls/ssl/server.pem tests/gold_tests/tls/ssl/server.key tests/gold_tests/io_uring/ssl/
```

- [ ] **Step 2: Write the failing autest**

Create `tests/gold_tests/io_uring/io_uring_tls.test.py` (idiom matches `io_uring_connect.test.py` + the TLS suite's cert setup):

```python
'''
TLS termination and outbound origin TLS over the io_uring net path.
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

Test.Summary = '''
With proxy.config.net.io_uring.enabled=1, terminate client TLS on a layered
SSLNetVConnection whose inner transport is an IOUringNetVConnection (accepted on
the ring, not epoll), and fetch from both a plain and a TLS origin so the
outbound (SSLNetProcessor::connect_re -> io_uring connectUp) leg is exercised.
'''

Test.SkipUnless(Condition.HasATSFeature('TS_USE_LINUX_IO_URING'))

Test.ContinueOnFail = True

ts = Test.MakeATSProcess("ts", enable_tls=True)
server = Test.MakeOriginServer("server")
tls_server = Test.MakeOriginServer("tls_server", ssl=True)

request_header = {"headers": "GET /plain HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "plain"
}
server.addResponse("sessionfile.log", request_header, response_header)

request_header = {"headers": "GET /tls HTTP/1.1\r\nHost: tls.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "tls"
}
tls_server.addResponse("sessionfile.log", request_header, response_header)

ts.addSSLfile("ssl/server.pem")
ts.addSSLfile("ssl/server.key")

ts.Disk.records_config.update({
    'proxy.config.net.io_uring.enabled': 1,
    'proxy.config.ssl.server.cert.path': ts.Variables.SSLDir,
    'proxy.config.ssl.server.private_key.path': ts.Variables.SSLDir,
    'proxy.config.ssl.client.verify.server.policy': 'DISABLED',
})

ts.Disk.ssl_multicert_yaml.AddLines(
    """
ssl_multicert:
  - dest_ip: "*"
    ssl_cert_name: server.pem
    ssl_key_name: server.key
""".split("\n"))

ts.Disk.remap_config.AddLine('map https://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))
ts.Disk.remap_config.AddLine('map https://tls.example.com https://127.0.0.1:{0}'.format(tls_server.Variables.SSL_Port))

# The load-bearing assertion: the TLS port's accept object is the io_uring one.
# Without the SSLNetProcessor::createNetAccept gate this line never appears and
# TLS accepts stay on the epoll SSLNetAccept.
ts.Disk.diags_log.Content = Testers.ContainsExpression(
    "io_uring accept enabled for TLS port", "TLS accepts must arm on the ring, not epoll")

tr = Test.AddTestRun("terminate TLS over io_uring, plain origin")
tr.MakeCurlCommand(
    '-s -o - -k --resolve www.example.com:{0}:127.0.0.1 "https://www.example.com:{0}/plain"'.format(ts.Variables.ssl_port),
    ts=ts)
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(tls_server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("plain", "body proxied back over TLS-terminated io_uring")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

tr = Test.AddTestRun("terminate TLS over io_uring, TLS origin (outbound leg)")
tr.MakeCurlCommand(
    '-s -o - -k --resolve tls.example.com:{0}:127.0.0.1 "https://tls.example.com:{0}/tls"'.format(ts.Variables.ssl_port),
    ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("tls", "body proxied from a TLS origin over io_uring both legs")
tr.StillRunningAfter = ts
tr.StillRunningAfter = tls_server
```

- [ ] **Step 3: Run it — verify it fails on the diags assertion**

```bash
cd tests && ./autest.sh --ats-bin /tmp/ats-dev/bin --sandbox /tmp/au-tls-route -f io_uring_tls
```

Expected: FAIL, specifically the `diags_log` `ContainsExpression("io_uring accept enabled for TLS port", ...)` tester (the curl runs may pass or fail — either is acceptable pre-change; the diags tester must fail).

- [ ] **Step 4: Expose `net_io_uring_enabled()`**

In `src/iocore/net/UnixNetProcessor.cc`, change the definition (pre-merge :34–40) from file-static to external:

```cpp
// proxy.config.net.io_uring.enabled (restart-required), read once.
bool
net_io_uring_enabled()
{
  static const bool enabled = RecGetRecordInt("proxy.config.net.io_uring.enabled").value_or(0) != 0;
  return enabled;
}
```

In `src/iocore/net/P_UnixNetProcessor.h`, add (inside the existing include guards, near the top-level declarations):

```cpp
#if TS_USE_LINUX_IO_URING
// proxy.config.net.io_uring.enabled (restart-required), read once at first use.
bool net_io_uring_enabled();
#endif
```

Ensure `P_UnixNetProcessor.h` sees `TS_USE_LINUX_IO_URING` (`#include "tscore/ink_config.h"` if not already transitively present).

- [ ] **Step 5: Gate `SSLNetProcessor::createNetAccept`**

In `src/iocore/net/SSLNetProcessor.cc`, add near the other includes:

```cpp
#if TS_USE_LINUX_IO_URING
#include "P_IOUringNetAccept.h"
#endif
```

and change `createNetAccept` (currently returning `new SSLNetAccept(opt)` unconditionally):

```cpp
NetAccept *
SSLNetProcessor::createNetAccept(const NetProcessor::AcceptOptions &opt)
{
#if TS_USE_LINUX_IO_URING
  // TLS rides the same transport gate as plain ports. The io_uring accept object
  // allocates the (gated, plain) inner VC via the unix netProcessor;
  // SSLNextProtocolAccept then layers the SSL VC over it, so nothing SSL-specific
  // is lost by not using SSLNetAccept here (its getNetProcessor() override is
  // unused on the TCP accept path).
  if (net_io_uring_enabled()) {
    Note("io_uring accept enabled for TLS port %d", opt.local_port);
    return new IOUringNetAccept(opt);
  }
#endif
  return new SSLNetAccept(opt);
}
```

If `SSLNetProcessor.cc` does not already include `P_UnixNetProcessor.h` (for `net_io_uring_enabled`), add it under the same `#if`.

- [ ] **Step 6: Build, install, rerun the test — verify it passes**

```bash
cmake --build build-dev -j"$(nproc)" && cmake --install build-dev
cd tests && ./autest.sh --ats-bin /tmp/ats-dev/bin --sandbox /tmp/au-tls-route -f io_uring_tls
```

Expected: PASS (both test runs + the diags assertion).

- [ ] **Step 7: Confirm no regression in the rest of the io_uring suite**

```bash
./autest.sh --ats-bin /tmp/ats-dev/bin --sandbox /tmp/au-tls-route2 -f $(ls gold_tests/io_uring/*.test.py | xargs -n1 basename | sed 's/\.test\.py//')
```

Expected: 22/22 (21 + the new test).

- [ ] **Step 8: Commit**

```bash
git add src/iocore/net/P_UnixNetProcessor.h src/iocore/net/UnixNetProcessor.cc src/iocore/net/SSLNetProcessor.cc tests/gold_tests/io_uring/io_uring_tls.test.py tests/gold_tests/io_uring/ssl/
git commit -m "io_uring: accept TLS ports on the ring

TLS ports previously always used the epoll SSLNetAccept even with
proxy.config.net.io_uring.enabled=1 (only the inner-VC allocation was
gated). Route SSLNetProcessor::createNetAccept through the same gate so
the accept, like the transport, is on the ring; the layered
SSLNetVConnection then wraps an IOUringNetVConnection unchanged."
```

---

### Task 4: Fix `SSLNetVConnection::reenable_re` foreign-VIO delegation

**Files:**
- Modify: `src/iocore/net/SSLNetVConnection.cc` (post-merge location of the pre-merge :3477–3482 definition)

**Interfaces:**
- Consumes: `SSLNetVConnection::reenable(VIO *)` — already dispatches user read/write VIOs to the matching transport VIO and handles buffered-rbio/terminated-transport drives.
- Produces: `reenable_re` with correct routing on both transports.

Background (why): the current body forwards the **user's** VIO straight to `_unvc->reenable_re(vio)`. `UnixNetVConnection::reenable_re` routes by `vio == &read.vio` on *itself*, so a foreign VIO always falls into the write branch — a user read-reenable would drive the transport write. Same misroute class on `IOUringNetVConnection::reenable`. Latent on both transports (the only in-tree path to `NetVConnection::reenable_re` is `VIO::reenable_re()`, which currently has no callers), so there is no test that can observe it; fix is one line and validated by build + suites.

- [ ] **Step 1: Apply the fix**

Replace:

```cpp
void
SSLNetVConnection::reenable_re(VIO *vio)
{
  ink_assert(_unvc != nullptr);
  _unvc->reenable_re(vio);
}
```

with:

```cpp
void
SSLNetVConnection::reenable_re(VIO *vio)
{
  // The vio here is the *user's* VIO; the inner VC routes reenable_re by
  // comparing against its own read.vio/write.vio, so forwarding a foreign VIO
  // would always take the write branch. Dispatch through our own reenable(),
  // which maps user VIO -> transport VIO. Deferred (non-inline) semantics are
  // within reenable_re's contract: the base itself falls back to reenable()
  // whenever the NetHandler lock is not already held.
  this->reenable(vio);
}
```

- [ ] **Step 2: Build, install**

```bash
cmake --build build-dev -j"$(nproc)" && cmake --install build-dev
```

Expected: clean build.

- [ ] **Step 3: TLS suite spot-check (epoll transport)**

```bash
cd tests && ./autest.sh --ats-bin /tmp/ats-dev/bin --sandbox /tmp/au-reenre -f io_uring_tls tls_flow_control tls_reload_under_load
```

Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add src/iocore/net/SSLNetVConnection.cc
git commit -m "ssl: route reenable_re through the layered VC's own dispatch

SSLNetVConnection::reenable_re forwarded the user's VIO to the inner
transport, whose reenable_re routes by identity against its own
read.vio/write.vio; a foreign VIO always fell into the write branch.
Dispatch through this->reenable(), which maps the user VIO to the
matching transport VIO. Deferred semantics are within reenable_re's
contract (the base falls back to reenable() without the NetHandler
lock)."
```

---

### Task 5: Force-on acceptance sweep — full TLS suite over io_uring

The TLS suite's tests don't set `net.io_uring.enabled`, so force it via a binary whose records default is 1 (the historical `build-forceon-*` pattern), and run the unmodified suite against it. This is the acceptance gate; it is also where spec frictions 1 (downgrade/abandon), 3 (dtor inline close), 4 (blind tunnel), and 5 (TLS-async) get their verification, via the named tests below.

**Files:**
- Temporary (never committed): one-character default flip in `src/records/RecordsConfig.cc`.
- Possibly modify (only if failures are root-caused to integration bugs): `src/iocore/net/IOUringNetVConnection.cc`, `src/iocore/net/SSLNetVConnection.cc`.

**Interfaces:**
- Consumes: baselines from Task 2 (epoll TLS-suite results) for differential comparison.
- Produces: TLS suite green at `enabled=1`; any integration bugs fixed and committed individually.

- [ ] **Step 1: Build the force-on binary**

```bash
cd /home/mo/work/trafficserver-io-uring
sed -i 's|"proxy.config.net.io_uring.enabled", RECD_INT, "0"|"proxy.config.net.io_uring.enabled", RECD_INT, "1"|' src/records/RecordsConfig.cc
grep -n 'io_uring.enabled' src/records/RecordsConfig.cc   # confirm default now "1"
cmake --preset claude-dev -B build-forceon -DCMAKE_INSTALL_PREFIX=/tmp/ats-forceon
cmake --build build-forceon -j"$(nproc)"
cmake --install build-forceon
git checkout -- src/records/RecordsConfig.cc              # revert immediately after the build
```

(If `cmake --preset ... -B ...` refuses the binaryDir override on this CMake version, configure explicitly: `cmake -B build-forceon -DCMAKE_BUILD_TYPE=Debug -DUSE_IOURING=ON -DBUILD_TESTING=ON -DCMAKE_INSTALL_PREFIX=/tmp/ats-forceon` mirroring the `dev` preset.)

- [ ] **Step 2: Run the full TLS suite against it**

```bash
cd tests && ./autest.sh --ats-bin /tmp/ats-forceon/bin --sandbox /tmp/au-forceon-tls -f $(ls gold_tests/tls/*.test.py | xargs -n1 basename | sed 's/\.test\.py//')
```

Expected: pass/fail equal to the Task 2 epoll baseline. Tests that specifically stand in for spec frictions — confirm these in particular:

| Spec friction | Covering test(s) |
|---|---|
| 1. downgrade write-cancel vs io_uring abandon (`_downgradeToPlain` → `do_io_write(nullptr)`; the abandon path's "re-drive for whatever the VIO holds now" is expected to compose — verify, don't pre-fix) | `allow-plain.test.py` |
| 3. SSL dtor inline `_unvc->do_io_close()` vs cancel-then-unwind deferred free | teardown-heavy tests: `tls_tunnel_timeout`, `tls_handshake_timeout`, `tls_origin_post_abort` (and the io_uring suite's teardown tests, re-run in Task 6) |
| 4. blind tunnel adopt + `_propagateHandShakeBuffer` NetState surgery over parked/foreign blocks | `tls_tunnel`, `tls_tunnel_forward`, `tls_partial_blind_tunnel` |
| 5. TLS-async wait-fd via the epoll→ring poll bridge | `tls_engine`, `tls_engine_teardown` (if these fail only here, mark friction 5 deferred per spec rather than blocking) |

- [ ] **Step 3: Triage each differential failure**

For every test failing at `enabled=1` but passing in the Task 2 baseline: rerun it solo; then debug with superpowers:systematic-debugging. Fix in the appropriate seam (`IOUringNetVConnection.cc` for transport-contract bugs, `SSLNetVConnection.cc` for layering bugs). One commit per root-caused fix, each with the failing test named in the body. Rebuild both `/tmp/ats-dev` and `/tmp/ats-forceon` (re-apply the sed for the latter, revert after) and rerun the failing test 3× before calling it fixed.

- [ ] **Step 4: Record the acceptance result**

Full-suite counts at `enabled=1` appended to the notes. The task is done when the differential vs Task 2 is zero (modulo failures proven pre-existing on `tls-refactor-wip` itself).

---

### Task 6: ASan sweep at enabled=1 (spec friction 6: buffer lifetime)

**Files:** none committed (temporary RecordsConfig flip again).

**Interfaces:**
- Consumes: green Task 5.
- Produces: ASan-clean evidence for the TLS-over-io_uring path (kernel-side write-after-free is ASan-invisible — the known class was fixed by `Ptr` anchors already on this branch and is regression-covered by the io_uring suite; ASan here targets userspace lifetime bugs in the new SSL↔io_uring interaction).

- [ ] **Step 1: Force-on ASan build**

```bash
sed -i 's|"proxy.config.net.io_uring.enabled", RECD_INT, "0"|"proxy.config.net.io_uring.enabled", RECD_INT, "1"|' src/records/RecordsConfig.cc
cmake --preset claude-dev-asan -B build-forceon-asan -DCMAKE_INSTALL_PREFIX=/tmp/ats-forceon-asan
cmake --build build-forceon-asan -j"$(nproc)"
cmake --install build-forceon-asan
git checkout -- src/records/RecordsConfig.cc
```

- [ ] **Step 2: Run the TLS suite + io_uring suite under ASan**

```bash
cd tests
./autest.sh --ats-bin /tmp/ats-forceon-asan/bin --sandbox /tmp/au-asan-tls -f $(ls gold_tests/tls/*.test.py | xargs -n1 basename | sed 's/\.test\.py//')
./autest.sh --ats-bin /tmp/ats-forceon-asan/bin --sandbox /tmp/au-asan-iou -f $(ls gold_tests/io_uring/*.test.py | xargs -n1 basename | sed 's/\.test\.py//')
```

Expected: same pass set as Task 5 (ASan timing skew may need single-test reruns), and **zero ASan reports** in any `traffic.out`/`error.log`:

```bash
grep -rl "AddressSanitizer" /tmp/au-asan-tls /tmp/au-asan-iou || echo CLEAN
```

Expected output: `CLEAN`. Any report: root-cause and fix (own commit) before proceeding; buffer-lifetime suspects start at the recv-destination pins and `_write_buf` block anchoring.

- [ ] **Step 3: Freelist spot-check on teardown-race tests (non-ASan binary)**

The freelist recycles outside malloc/free, so it masks userspace UAF from ASan-less *and* ASan builds alike; `traffic_server -f` disables it so a stale-pointer write hits genuinely freed memory. There is no per-test knob, so temporarily patch the autest extension for this one scratch run (never committed):

```bash
cd /home/mo/work/trafficserver-io-uring
sed -i "s/^    ts_args = ''$/    ts_args = ' -f'/" tests/gold_tests/autest-site/trafficserver.test.ext
grep -n "ts_args = " tests/gold_tests/autest-site/trafficserver.test.ext   # confirm the injection
cd tests && ./autest.sh --ats-bin /tmp/ats-forceon/bin --sandbox /tmp/au-freelist \
  -f io_uring_tls io_uring_close_inflight tls_tunnel_timeout allow-plain
cd .. && git checkout -- tests/gold_tests/autest-site/trafficserver.test.ext
```

Expected: all listed tests pass and no crash/`Fatal` in any sandbox `traffic.out`. This catches userspace UAF only (kernel writes bypass it — that class is regression-covered by the io_uring suite's existing pin tests).

**Files:**
- Modify (out of tree): `~/work/io-uring-coro-bench/` — add a TLS workload variant to the existing measure scripts.
- Create (in tree, committed): results section in `experiments/coro-net-prototype/PERF-RESULTS-2026-07-04-tls.md` (new file, same conventions as `PERF-RESULTS-2026-06-28.md`).

**Interfaces:**
- Consumes: Tasks 1–6 complete; the rig's existing pattern — one force-default binary, A/B toggled via `proxy.config.net.io_uring.enabled` in records, cgroup-cpuset pinning via `setup-box.sh`.
- Produces: committed A/B numbers (req/s, CPU/1k-req, p50/p99) for at least {small object, large object} × {enabled=0, enabled=1} over HTTPS.

- [ ] **Step 1: Release build for measurement**

Use the existing `build-rel` configuration with the merged tree (do NOT measure the Debug build):

```bash
cmake --build build-rel -j"$(nproc)" && cmake --install build-rel   # reconfigure first if build-rel predates the merge; keep its existing install prefix
```

- [ ] **Step 2: Extend the rig with an HTTPS workload**

In `~/work/io-uring-coro-bench/`, clone the existing measure script pair to an `-tls` variant: same origin/objects, ATS remap targets `https://` on the TLS port, client uses TLS (wrk2/curl per rig convention) with session resumption disabled first run, enabled as a second dimension only if time permits. The A/B toggle stays `proxy.config.net.io_uring.enabled=0|1` in the run's records config — same binary.

- [ ] **Step 3: Validate the harness before trusting numbers**

The silent-failure checklist, all mandatory: remap key has NO `:port`; every response validated HTTP 200 + full body size; cache file pre-created with `truncate` if the workload is cache-hit; RAM-hit proven via `cache_hit_mem_fresh`; ATS pinned via cgroup v2 cpuset (`setup-box.sh`), not taskset; watch %iowait separately from %idle.

- [ ] **Step 4: Run the campaign**

6 rounds per cell, cells = {small (~4KB), large (~1MB)} × {enabled=0, enabled=1}, fixed connection count matching the earlier plain-HTTP campaign for comparability. Record req/s, CPU/1k-req, p50/p99 per round; report medians with min–max.

- [ ] **Step 5: Write up and commit results**

Create `experiments/coro-net-prototype/PERF-RESULTS-2026-07-04-tls.md` with: setup (hardware, pinning, binary SHA, OpenSSL version), the four cells' tables, and a short qualified conclusion (conditions under which each side wins; no unconditional claims). Commit:

```bash
git add experiments/coro-net-prototype/PERF-RESULTS-2026-07-04-tls.md
git commit -m "experiments: TLS-over-io_uring vs TLS-over-epoll A/B results"
```

---

## Notes / recorded baselines

(appended during execution)
