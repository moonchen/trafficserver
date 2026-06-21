/** @file
 *
 *  SEAM 1 — the I/O backend boundary.
 *
 *  This header defines the *only* contract between the asynchronous I/O engine
 *  (epoll or io_uring) and everything above it. The crucial design property is
 *  that the backend knows nothing about coroutines, NetVConnections, VIOs, or
 *  ATS. It understands exactly one thing: an `IoOp`. It is handed a pointer to
 *  an IoOp, it makes the operation happen, it writes the result into the op, and
 *  it reports the op back as "completed". Who waits on that op, and what resuming
 *  it means, is none of the backend's business.
 *
 *  Compare this to the two WIP branches:
 *    - net-iouring: the backend (IOUringContext) reaches *up* into the net layer
 *      via a virtual `IOUringCompletionHandler::handle_complete(cqe)` — the
 *      backend dispatches directly into VConnection code.
 *    - async-net: the backend (NetAIO::TCPConnection) reaches up via a virtual
 *      `TCPConnectionObserver` with five callbacks.
 *  Here the backend has a *single* outbound concept ("this op is done") and does
 *  not call up at all — it just makes completed ops collectable. The coroutine
 *  layer (Seam 2) decides what running a continuation means.
 */
#pragma once

#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <sys/socket.h>

namespace coronet
{

// A single asynchronous I/O operation. One of these lives *inside the coroutine
// frame* of whoever is awaiting it (see async_socket.h). That is the whole
// lifetime trick: the op — and the buffer it points at — is guaranteed to stay
// alive for exactly as long as the operation is in flight, because the awaiting
// coroutine is suspended (its frame pinned) until the op completes. Neither WIP
// branch got this for free: net-iouring had to hoist msghdr/iovec to class scope
// after a use-after-scope crash; async-net heap-allocated a unique_ptr<msghdr>
// per I/O. Here it is structural and zero-extra-allocation.
struct IoOp {
  enum class Type { Recv, Send, Connect, Accept, Close };

  Type type{};
  int  fd{-1};

  // Recv/Send payload.
  void  *buf{nullptr};
  size_t len{0};

  // Connect (in) / Accept (out) address.
  sockaddr  *addr{nullptr};
  socklen_t *addrlen{nullptr};

  // Result, in syscall convention: >= 0 on success (bytes, or accepted fd),
  // or -errno on failure. Cancelled ops complete with -ECANCELED.
  int result{0};

  // Who to resume when this op completes. Set by the awaitable, consumed by the
  // reactor — never by the backend (the backend only *reports* completion).
  // Because each thread submits to its own backend, this op was submitted on the
  // owner thread and completes on the owner thread: the resume is thread-local,
  // no lock required (see reactor.h / README on why no per-VC mutex is needed).
  std::coroutine_handle<> waiter{};

  // Backend-private bookkeeping (e.g. epoll interest list membership). Opaque
  // above Seam 1.
  void *backend_state{nullptr};
};

// The backend interface. Two real implementations: EpollBackend, UringBackend.
class IBackend
{
public:
  virtual ~IBackend() = default;

  // Begin `op`. Non-blocking: returns immediately. The op completes later and is
  // surfaced through poll(). `op` must outlive the in-flight operation (it does,
  // because it lives in the awaiting coroutine frame).
  virtual void submit(IoOp *op) = 0;

  // Best-effort cancel of an in-flight op. The *original* op is still reported
  // as completed (with -ECANCELED) — the caller awaits that completion before
  // tearing anything down. This is what makes safe close possible; net-iouring
  // skipped it (`// TODO: cancel in-flight ops`) and `delete this`'d into a UAF.
  virtual void cancel(IoOp *op) = 0;

  // Wait up to `timeout_ms` for I/O, then append every op that completed to
  // `completed`. Does NOT resume anybody — resumption is Seam 2's job, performed
  // on the reactor thread under the right lock. This split (detect completion in
  // the backend, run the continuation in the reactor) mirrors ATS draining CQEs
  // and *then* walking the ready list.
  virtual void poll(int timeout_ms, std::vector<IoOp *> &completed) = 0;

  // A human name for logging which engine is in use.
  virtual const char *name() const = 0;
};

} // namespace coronet
