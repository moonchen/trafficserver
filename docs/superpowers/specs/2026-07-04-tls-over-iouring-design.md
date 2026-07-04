# TLS over io_uring — integration design

Goal: a working prototype where TLS traffic (both directions) runs over the
io_uring coroutine transport, validated by the TLS gold-test suite, followed
by a perf A/B of TLS-over-io_uring vs TLS-over-epoll.

## Inputs

- `io-uring-coroutine-wip` — 109 commits on master@`b13b9858ac`. C++20-coroutine
  io_uring net path: `IOUringNetVConnection : public UnixNetVConnection`
  (`src/iocore/net/P_IOUringNetVConnection.h`), plain TCP only. Selection is
  `proxy.config.net.io_uring.enabled` (restart-scoped), read in
  `UnixNetProcessor::allocate_vc` / `createNetAccept` and
  `NetHandler::waitForActivity`.
- `tls-refactor-wip` @ `d271d16c36` — squash `31697718a0` + gold tests, on
  master@`46346ba402` (571 commits newer than the io_uring base). The refactored
  `SSLNetVConnection` is a layered VC: handed a connected `UnixNetVConnection*`
  in `startEvent` (NET_EVENT_ACCEPT/OPEN), arms two transport VIOs
  (`do_io_read`/`do_io_write` with INT64_MAX into its own `_read_buf`/`_write_buf`),
  and owns no fd/epoll/NetHandler state of its own.

Branch topology facts (2026-07-04): feature-diff overlap is 4 files; the master
delta touches ~12 io_uring-modified files, concentrated in
`UnixNet{,Accept,Processor}.cc`.

## Git strategy (decided)

New branch `io-uring-tls-wip` off `io-uring-coroutine-wip`; merge
`tls-refactor-wip` into it. Three-way merge from base `b13b9858ac` absorbs the
master delta; conflicts confined to roughly the 12 net files. Both source
branches stay intact and independently upstreamable.

Rejected: rebasing the 109 io_uring commits onto the TLS branch (repeated
conflict resolution, days of mechanical work, source branch rewritten) and
cherry-picking the TLS squash backwards (moves the refactor 571 commits behind
the master it was developed and parity-tested against).

## Architecture

The layered SSL VC is transport-agnostic by construction; `IOUringNetVConnection`
is a `UnixNetVConnection` that participates in NetHandler (open/enable/ready
lists, InactivityCop) with completion-driven I/O underneath (`ep.syscall=false`,
fd never in epoll). Integration = merge + route SSL ports' inner VCs through the
existing io_uring gate + fix enumerated frictions. One knob flips the transport
under TLS; the perf A/B runs one binary with `enabled=0` vs `1`.

## Routing changes

- **Inbound:** post-merge, `NetAccept` allocates the plain inner VC via the
  io_uring-gated `unix_netProcessor.allocate_vc`, and `SSLNextProtocolAccept::mainEvent`
  wraps it with the SSL VC (allocated from `ssl_NetProcessor.allocate_vc`) and
  starts the handshake. Gap to close: `SSLNetProcessor::createNetAccept` returns
  the epoll `SSLNetAccept` unconditionally. Make SSL ports follow the same gate
  as `UnixNetProcessor::createNetAccept` (io_uring accept object + forced
  per-ET_NET-thread accept), so accepted inner VCs are io_uring VCs. The accept
  object must allocate the *plain* inner VC (as merged `NetAccept` sites do),
  never an SSL VC.
- **Outbound:** `SSLNetProcessor::connect_re` allocates the SSL VC as the
  continuation and delegates to `unix_netProcessor.connect_re` → gated
  `allocate_vc` → `IOUringNetVConnection::connectUp` → `NET_EVENT_OPEN` →
  SSL `startEvent` adopts the inner VC. Expected to fall out of the merge;
  verify only.
- Session pools stay thread-scoped: the startup `Fatal()` for
  `server_session_sharing.pool != thread` with io_uring remains. The SSL
  `migrateToCurrentThread` path is therefore unreachable at `enabled=1`.

## Known frictions (fix or verify, each has a concrete site)

1. **Downgrade write-cancel vs abandon.** `_downgradeToPlain` cancels the
   transport write VIO via `_unvc->do_io_write(nullptr, 0, nullptr)`; the
   io_uring override treats `do_io_write(nullptr)` as tunnel-teardown
   "write abandoned" (cancels in-flight send, marks `_write_abandoned`).
   Downgrade returns the transport for continued plain use, so abandon
   semantics are wrong there. Fix: distinguish VIO-cancel from abandon in
   `IOUringNetVConnection::do_io_write`.
2. **`reenable_re` foreign-VIO delegation.** `SSLNetVConnection::reenable_re`
   forwards the *user's* VIO to `_unvc->reenable_re(vio)` — a VIO the inner VC
   doesn't own. io_uring's `reenable_re` is deliberately deferred-only. Audit
   the foreign-VIO handling; likely fix the delegation to map user VIO →
   corresponding transport VIO (arguably a latent refactor bug independent of
   io_uring).
3. **SSL dtor inline-close fast path** touches `_unvc->nh` and takes
   `nh->mutex` around `_unvc->do_io_close()`. The io_uring VC has an `nh`, and
   its `do_io_close` is cancel-then-unwind with deferred free; verify the fast
   path composes (it should — the deferral is internal to the io_uring VC).
4. **Blind tunnel & handshake-buffer propagation.**
   `TunnelNetVConnection::adopt(UnixNetVConnection*)` and
   `_propagateHandShakeBuffer` (NetState surgery + `readSignalDone`) operate on
   inner-VC internals; the io_uring read path parks held bytes / foreign
   provided-buffer blocks and supports re-targeted MIOBuffer delivery. Should
   compose; verify with the tunnel gold tests.
5. **TS_USE_TLS_ASYNC** registers the OpenSSL async wait-fd in the thread's
   epoll (`AsyncTLSEventIO`); io_uring threads bridge the thread epoll fd into
   the ring (`IOUringPollBridge`), so it should still fire. Validate via the
   existing `tls_engine` test if it runs at `enabled=1`; otherwise defer —
   out of prototype scope.
6. **Provided-buffer foreign blocks in the rbio.** Kernel ring-buffer blocks
   are appended read-only into the SSL VC's `_read_buf` (the `BIO_s_miobuffer`
   rbio). Reads only consume, so fine in principle, but this bug class bit
   before (recv-buffer UAF) — the ASan + freelist-diagnostic pass is mandatory.

Also check post-merge: whether the read-side `_isReadyToTransferData` gate
still exists in the merged `UnixNetVConnection` (the refactor likely removed
its purpose; the io_uring read drives never had it — harmless only if the
layered model made it vestigial).

## Error handling

No new mechanisms; the two sides' invariants must compose. Teardown is the new
interaction surface: the SSL VC dtor calling `_unvc->do_io_close()` with ring
ops in flight must land in io_uring's cancel-then-unwind deferred free. The
io_uring gold suite's teardown-race tests cover this at `enabled=1`; failures
there are treated as contract bugs in the integration, not flakes (run solo
before believing any SEGV — known port-collision gotcha).

## Validation ladder

1. Merged tree builds (`build-dev` preset, `-DUSE_IOURING=1`) and
   `cmake --install` (autests run the installed tree).
2. Regression: io_uring 21-test gold suite at `enabled=1` (plain HTTP), TLS
   gold suite at `enabled=0` — both must match pre-merge results.
3. Acceptance: TLS gold suite forced `net.io_uring.enabled=1`, including
   `tls_flow_control`, `tls_reload_under_load`, proxy-protocol and tunnel
   tests.
4. ASan run of the TLS suite at `enabled=1`; freelist `-f` spot-check on
   teardown-race tests.
5. Perf A/B: one binary, `enabled=0` vs `1`, TLS workload — extend the
   `~/work/io-uring-coro-bench` rig (FP-binary toggle pattern carries over),
   observing the benchmarking-pitfalls checklist (remap key without :port,
   validate 200 + body size, pre-created cache file, cgroup cpuset pinning).

## Out of scope

QUIC, deep TLS-async validation, global/hybrid session pools (startup
`Fatal()` stays), history reshaping for upstream.
