# TLS-refactor LSan leak notes (BoringSSL build)

Date: 2026-06-03. Branch `tls-refactor-wip` @ c8398b7464. Merge-base with mainline
(pre-refactor fork point): `09c4f8a12`.

## How this was produced
- Build: `build-bssl-asan` = ASAN + BoringSSL (`OPENSSL_ROOT_DIR=/home/mo/work/boringssl-root`,
  `ENABLE_ASAN=ON`, `ENABLE_AUTEST=ON`), installed to `/tmp/ts-bssl-asan`.
- Ran the full 74-test TLS suite (`gold_tests/tls` + `tls_hooks`) under LSan with
  **`traffic_server -F`** (allocator freelist OFF — both the class FreelistAllocator,
  `ink_queue.cc:133`, and the per-thread ProxyAllocator cache, `ProxyAllocator.cc:33`,
  so every alloc/free is a real malloc/free and LSan is not blinded by pooling).
- LSan capture via `ASAN_OPTIONS=...:log_path=...:log_exe_name=1`; analysis filtered to
  `asan.traffic_server.*` only (the test's own `ssl-post` client and `traffic_crashlog`
  are separate ASAN binaries and were excluded).
- Suppression list: `tls_autest.txt` (this directory).
- `-F` was injected into the autest-launched traffic_server via a temporary, env-gated
  passthrough added to `tests/gold_tests/autest-site/trafficserver.test.ext` (in
  `MakeATSProcess`, after the `--block` handling):
  ```python
  extra_ts_args = os.environ.get('TS_EXTRA_ARGS')
  if extra_ts_args:
      ts_args += ' ' + extra_ts_args
  ```
  then run with `TS_EXTRA_ARGS='-F'`. This edit was reverted after the run; re-apply it
  to reproduce. Full run recipe (from `build-bssl-asan/tests`):
  ```sh
  TS_EXTRA_ARGS=-F LD_LIBRARY_PATH=/home/mo/work/boringssl-root/lib \
  ASAN_OPTIONS='detect_leaks=1:abort_on_error=0:exitcode=0:log_path=/tmp/lsan/asan:log_exe_name=1' \
  LSAN_OPTIONS='max_leaks=0:print_suppressions=1:suppressions=<repo>/ci/asan_leak_suppression/tls_autest.txt' \
  xargs python3 autest-parallel.py -j3 --ats-bin /tmp/ts-bssl-asan/bin \
    --build-root <repo>/build-bssl-asan --sandbox /tmp/sb < /tmp/tls_filters.txt
  # then inspect asan.traffic_server.* (ignore asan.ssl-post.* / asan.traffic_crashlog.*)
  ```

## Headline result
- **No refactor-introduced leak (bucket C) found.** The refactored `SSLNetVConnection`
  lifecycle is sound: `~SSLNetVConnection` (SSLNetVConnection.cc:1017, `_ssl=nullptr` ->
  `SSL_free`) is reached from every terminal path via `free_thread`, and frees `_ssl`,
  the layered rbio/wbio BIOs, `_read_buf`/`_write_buf`, the handshake reader, and `_unvc`
  exactly once. Reparenting branches (`_downgradeToPlain`, `_handoffBlindTunnel`) release
  the handed-off buffer/transport before close. Mainline at the merge-base freed SSL
  identically (only on close); the refactor merely moved `SSL_free` into the `unique_ptr`
  deleter. Control: the basic `tls` test (40 inbound POSTs completed before stop) leaks
  ZERO SSL/VC/session objects.
- Every leak LSan reports under autest is either a one-time startup singleton, a
  config object held at the SIGINT fast-exit, or in-flight connection/transaction state
  at the fast-exit — all bounded and suppressed (bucket A) — except the two genuine,
  pre-existing, non-refactor leaks below (bucket B), which are suppressed *and* recorded
  here for a separate fix.

## Genuine leaks to fix in a later session (PRE-EXISTING, not the TLS refactor)

### B1. EVP_PKEY leaked per key load — `SSLPrivateKeyHandler`
- Alloc: `src/iocore/net/SSLUtils.cc:934` `pkey = PEM_read_bio_PrivateKey(...)`
  (engine variant ~:917), attached via `SSL_CTX_use_PrivateKey(ctx, pkey)` at `:940`.
- Bug: the success path (`:940`-`952`) returns `true` without `EVP_PKEY_free(pkey)`.
  `SSL_CTX_use_PrivateKey` takes its own reference, so the caller's reference leaks; it
  is NOT reclaimed by a later `SSL_CTX_free`. Only the error paths (`:921`, `:943`) free.
- Growth: one EVP_PKEY per key load. Reached at startup (`_store_ssl_ctx`) AND at runtime
  via `TSSslSecretSet -> SSLConfigParams::updateCTX -> update_ssl_ctx -> init_server_ssl_ctx
  -> load_certs` — so it **grows per config reload / per secret set** (observed 36 and 84
  objects in heavy procs, not a fixed 2).
- Not refactor: `git show 09c4f8a12:src/iocore/net/SSLUtils.cc` lines 910-953 are
  byte-identical to HEAD; blame dates the success/return block to 2014-2024 (pre-refactor).
- Proposed fix: add `EVP_PKEY_free(pkey);` after the successful `SSL_CTX_use_PrivateKey`
  (or use a `bssl::UniquePtr<EVP_PKEY>` for the caller's ref).

### B2. ConfigReloadProgress continuation leaked per reload — `ConfigReloadTask::start_progress_checker`
- Alloc: `src/mgmt/config/ConfigReloadTrace.cc:393` `auto *checker = new
  ConfigReloadProgress(shared_from_this());` then `eventProcessor.schedule_in(checker, ...)`.
- Bug: `ConfigReloadProgress::check_progress` returns `EVENT_DONE` on terminal/timeout
  (`:417`, `:457`) but never `delete this`; the event system frees the `Event` wrapper,
  never the continuation. No `~ConfigReloadProgress` / `delete this` anywhere. So it leaks
  even on the normal successful-completion path (not just at shutdown).
- Growth: one per `traffic_ctl config reload` -> **grows per reload** (unbounded).
- Not refactor: `git log 09c4f8a12..HEAD` touches none of `ConfigReloadTrace.cc` /
  `ReloadCoordinator.cc`; diff vs merge-base is empty. Pure mgmt/rpc subsystem.
- Proposed fix: `delete this;` before each `return EVENT_DONE;` in `check_progress`
  (or own the checker via a smart pointer tied to the task).

## Latent (non-heap) observation — not an LSan leak, noted for completeness
- `~EventIO` (`include/iocore/net/EventIO.h:97`) is empty and does not call
  `stop()`, so a VC torn down mid-async-handshake would not deregister `async_ep`'s epoll
  fd. Not exercised here (`proxy.config.ssl.async_handshake.enabled` defaults to 0;
  `AsyncTLSEventIO` holds no heap state), and it is an fd/epoll concern, not a heap leak.
  Worth a look if async TLS handshake is enabled in production.

## Bounded shutdown artifacts (bucket A — suppressed, NOT real leaks)
For reference, the suppressed-but-benign categories and why each is bounded:
- One-time startup: `Log::create_threads` (logging threads).
- Config held at fast-exit (freed on reload / bounded by config size): client SSL_CTX
  (`SSLConfigParams::getCTX`), server cert/chain (`SSLMultiCertConfigLoader::load_certs`),
  test-plugin global hooks (`setup_callbacks`).
- In-flight at fast-exit (bounded by concurrency; verified normal-close free path):
  origin H2 session (`Http2ServerSession::Http2ServerSession`), `SSLProxySession`
  (`ProxySession::_handle_if_ssl`), in-flight H2 stream mutex
  (`Http2ConnectionState::create_stream`), the in-flight SSL object + layered BIOs
  (`SSLNetVConnection::_make_ssl_connection`), and the BoringSSL outbound-handshake
  subtree (`SSLNetVConnection::_ssl_connect`).
- In-flight OUTBOUND origin connection/transaction state, owned by the in-flight VC/HttpSM
  at the SIGINT fast-exit: the outbound `SSLNetVConnection` + its `_read_buf`/`_write_buf`
  and the strdup'd `NetVCOptions` (`SSLNetProcessor::connect_re`), the SSL+BIO objects
  (`_make_ssl_connection`), and the BoringSSL handshake/cert/session subtree (`_ssl_connect`).
  This is nondeterministic: the volume depends on how many origin connections are mid-flight
  when autest stops the proxy (observed 0.2 MB in one run, 7.4 MB in another). `connect_re`
  is a relatively broad frame (it roots the whole synchronous outbound-setup subtree) — that
  breadth is accepted because (a) it is outbound-only, (b) the VC free path is verified sound,
  and (c) the calibration control shows completed connections leak nothing.

CAVEAT: the symmetric INBOUND in-flight case (a client connection still open at fast-exit)
was NOT observed here (the proxy-verifier client completes and closes before autest stops
ATS), so the inbound accept-path VC-ctor buffers are intentionally NOT suppressed — leaving
them visible. If a future test holds inbound connections open at teardown, expect a small
bounded inbound VC-buffer residual of the same artifact class.

VERIFICATION: with this suppression list the full 74-test suite was clean (0 unsuppressed
leaks in all 98 traffic_server processes) on two independent runs, including one with heavy
in-flight outbound state (7.4 MB caught by `connect_re`).

These would all disappear if autest drained connections before exit (it sends SIGINT with
`shutdown_timeout=0`). They are not regressions.
