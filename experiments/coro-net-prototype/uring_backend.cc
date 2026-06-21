#ifdef HAVE_LIBURING

#include "uring_backend.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>

namespace coronet
{

UringBackend::UringBackend(unsigned entries)
{
  int rc = ::io_uring_queue_init(entries, &_ring, 0);
  if (rc < 0) {
    ::fprintf(stderr, "io_uring_queue_init: %s\n", ::strerror(-rc));
    ::abort();
  }
}

UringBackend::~UringBackend()
{
  ::io_uring_queue_exit(&_ring);
}

// Unlike net-iouring's `ink_release_assert(sqe != nullptr)`, a full ring is a
// recoverable state: submit what we have to make room, then try once more.
io_uring_sqe *
UringBackend::get_sqe()
{
  io_uring_sqe *sqe = ::io_uring_get_sqe(&_ring);
  if (sqe == nullptr) {
    ::io_uring_submit(&_ring);
    sqe = ::io_uring_get_sqe(&_ring);
  }
  return sqe; // caller checks; in this prototype the ring is sized generously
}

void
UringBackend::submit(IoOp *op)
{
  io_uring_sqe *sqe = get_sqe();
  if (sqe == nullptr) {
    op->result = -EAGAIN; // would-block on the SQ itself; surface, don't crash
    // (a production version would park the op on a retry queue)
    return;
  }

  switch (op->type) {
  case IoOp::Type::Recv:
    ::io_uring_prep_recv(sqe, op->fd, op->buf, op->len, 0);
    break;
  case IoOp::Type::Send:
    ::io_uring_prep_send(sqe, op->fd, op->buf, op->len, MSG_NOSIGNAL);
    break;
  case IoOp::Type::Accept:
    ::io_uring_prep_accept(sqe, op->fd, op->addr, op->addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    break;
  case IoOp::Type::Connect:
    ::io_uring_prep_connect(sqe, op->fd, op->addr, *op->addrlen);
    break;
  case IoOp::Type::Close:
    ::io_uring_prep_close(sqe, op->fd);
    break;
  }
  // The IoOp pointer IS the user_data — this is the entire backend->waiter link.
  ::io_uring_sqe_set_data(sqe, op);
  ::io_uring_submit(&_ring);
}

void
UringBackend::cancel(IoOp *op)
{
  io_uring_sqe *sqe = get_sqe();
  if (sqe == nullptr) {
    return;
  }
  // Cancel by user_data: the kernel matches the in-flight op submitted with this
  // same pointer and completes *it* with -ECANCELED.
  ::io_uring_prep_cancel(sqe, op, 0);
  ::io_uring_sqe_set_data(sqe, CANCEL_MARKER);
  ::io_uring_submit(&_ring);
}

void
UringBackend::poll(int timeout_ms, std::vector<IoOp *> &completed)
{
  __kernel_timespec ts{.tv_sec = timeout_ms / 1000, .tv_nsec = (timeout_ms % 1000) * 1000000L};

  io_uring_cqe *cqe = nullptr;
  // Submit anything pending and block until at least one completion or timeout.
  ::io_uring_submit_and_wait_timeout(&_ring, &cqe, 1, &ts, nullptr);

  unsigned head;
  unsigned count = 0;
  io_uring_for_each_cqe(&_ring, head, cqe)
  {
    ++count;
    void *data = ::io_uring_cqe_get_data(cqe);
    if (data == nullptr || data == CANCEL_MARKER) {
      continue; // the cancel SQE's own completion — ignore
    }
    IoOp *op   = static_cast<IoOp *>(data);
    op->result = cqe->res; // already -errno on failure, bytes/fd on success
    completed.push_back(op);
  }
  ::io_uring_cq_advance(&_ring, count);
}

} // namespace coronet

#endif // HAVE_LIBURING
