/** @file
 *  An epoll implementation of IBackend.
 *
 *  This is the "readiness" model: epoll tells us a fd is ready, and the backend
 *  then performs the actual recv/send/accept/connect syscall and reports the
 *  result. It is exactly the engine async-net's NetAIO sat on. Notice it
 *  satisfies the *same* IBackend interface the io_uring engine does — that
 *  identical seam is the whole point. Above Seam 1 nothing knows or cares which
 *  one is running.
 */
#pragma once

#include "io_backend.h"

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace coronet
{

class EpollBackend final : public IBackend
{
public:
  EpollBackend();
  ~EpollBackend() override;

  void submit(IoOp *op) override;
  void cancel(IoOp *op) override;
  void poll(int timeout_ms, std::vector<IoOp *> &completed) override;
  const char *
  name() const override
  {
    return "epoll";
  }

private:
  // Per-fd interest: at most one read-side op and one write-side op outstanding,
  // matching the one-per-direction model real net VConnections use.
  struct FdState {
    IoOp    *read{nullptr};  // Recv or Accept
    IoOp    *write{nullptr}; // Send or Connect
    uint32_t interest{0};    // currently-registered epoll events
  };

  // Run the syscall now. Returns true if the op completed (pushed to
  // `completed`); false if it would block and should stay armed.
  bool perform(IoOp *op, std::vector<IoOp *> &completed);
  void rearm(int fd, FdState &st); // recompute epoll interest

  int                              _epfd{-1};
  std::unordered_map<int, FdState> _fds;
  std::vector<IoOp *>              _ready; // inline-completed (close, cancel)
};

} // namespace coronet
