/** @file
 *  An io_uring implementation of IBackend (built only when liburing is present;
 *  guarded by HAVE_LIBURING).
 *
 *  Where the epoll backend waits for *readiness* and then does the syscall, this
 *  one hands the whole operation to the kernel (SQE) and collects the *result*
 *  (CQE). Same IBackend interface, so the coroutine and NetVConnection layers
 *  above are byte-for-byte identical regardless of which engine is selected at
 *  startup. That interchangeability is exactly what neither WIP branch had:
 *  async-net was epoll-only, net-iouring was io_uring-only, each with the engine
 *  welded into the VConnection.
 *
 *  Two things this backend gets right that net-iouring left as TODOs:
 *    - cancel() issues a real IORING_OP_ASYNC_CANCEL, so close can drain
 *      in-flight ops instead of `delete this`-ing under them.
 *    - submit() handling of a full submission queue is a recoverable condition,
 *      not an ink_release_assert crash (here we simply flush and retry).
 */
#pragma once

#ifdef HAVE_LIBURING

#include "io_backend.h"

#include <liburing.h>
#include <vector>

namespace coronet
{

class UringBackend final : public IBackend
{
public:
  explicit UringBackend(unsigned entries = 256);
  ~UringBackend() override;

  void submit(IoOp *op) override;
  void cancel(IoOp *op) override;
  void poll(int timeout_ms, std::vector<IoOp *> &completed) override;
  const char *
  name() const override
  {
    return "io_uring";
  }

private:
  io_uring_sqe *get_sqe(); // get an SQE, flushing the ring if it is full

  io_uring _ring{};

  // Sentinel stored as user_data on the cancel SQE itself, so we can recognise
  // and discard the cancel op's own completion (we only care about the original
  // op completing with -ECANCELED).
  static inline void *const CANCEL_MARKER = reinterpret_cast<void *>(1);
};

} // namespace coronet

#endif // HAVE_LIBURING
