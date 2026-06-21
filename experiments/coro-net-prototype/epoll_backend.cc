#include "epoll_backend.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace coronet
{

EpollBackend::EpollBackend()
{
  _epfd = ::epoll_create1(EPOLL_CLOEXEC);
  if (_epfd < 0) {
    ::perror("epoll_create1");
    ::abort();
  }
}

EpollBackend::~EpollBackend()
{
  if (_epfd >= 0) {
    ::close(_epfd);
  }
}

void
EpollBackend::rearm(int fd, FdState &st)
{
  uint32_t want = (st.read ? uint32_t{EPOLLIN} : 0u) | (st.write ? uint32_t{EPOLLOUT} : 0u);
  if (want == st.interest) {
    return;
  }
  if (want == 0) {
    ::epoll_ctl(_epfd, EPOLL_CTL_DEL, fd, nullptr);
    _fds.erase(fd);
    return;
  }
  epoll_event ev{};
  ev.events  = want;
  ev.data.fd = fd;
  int op     = (st.interest == 0) ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
  if (::epoll_ctl(_epfd, op, fd, &ev) < 0) {
    ::perror("epoll_ctl");
  }
  st.interest = want;
}

void
EpollBackend::submit(IoOp *op)
{
  switch (op->type) {
  case IoOp::Type::Close:
    // Nothing to wait for; do it now and report inline.
    ::close(op->fd);
    op->result = 0;
    _ready.push_back(op);
    return;
  case IoOp::Type::Recv:
  case IoOp::Type::Accept: {
    FdState &st = _fds[op->fd];
    st.read     = op;
    rearm(op->fd, st);
    return;
  }
  case IoOp::Type::Send: {
    FdState &st = _fds[op->fd];
    st.write    = op;
    rearm(op->fd, st);
    return;
  }
  case IoOp::Type::Connect: {
    // Unlike io_uring's prep_connect, epoll needs us to start the connect now,
    // then wait for writability to discover the outcome.
    int rc = ::connect(op->fd, op->addr, *op->addrlen);
    if (rc == 0) {
      op->result = 0;
      _ready.push_back(op);
      return;
    }
    if (errno != EINPROGRESS) {
      op->result = -errno;
      _ready.push_back(op);
      return;
    }
    FdState &st = _fds[op->fd];
    st.write    = op;
    rearm(op->fd, st);
    return;
  }
  }
}

void
EpollBackend::cancel(IoOp *op)
{
  auto it = _fds.find(op->fd);
  if (it == _fds.end()) {
    return;
  }
  FdState &st = it->second;
  bool     hit = false;
  if (st.read == op) {
    st.read = nullptr;
    hit     = true;
  }
  if (st.write == op) {
    st.write = nullptr;
    hit      = true;
  }
  if (hit) {
    op->result = -ECANCELED;
    _ready.push_back(op);
    rearm(op->fd, st); // note: may erase the FdState; do it last
  }
}

// Run the actual syscall for a now-ready op and record the result.
bool
EpollBackend::perform(IoOp *op, std::vector<IoOp *> &completed)
{
  ssize_t r = 0;
  switch (op->type) {
  case IoOp::Type::Recv:
    r = ::recv(op->fd, op->buf, op->len, 0);
    break;
  case IoOp::Type::Send:
    r = ::send(op->fd, op->buf, op->len, MSG_NOSIGNAL);
    break;
  case IoOp::Type::Accept:
    r = ::accept4(op->fd, op->addr, op->addrlen, SOCK_NONBLOCK | SOCK_CLOEXEC);
    break;
  case IoOp::Type::Connect: {
    int       err = 0;
    socklen_t l   = sizeof(err);
    ::getsockopt(op->fd, SOL_SOCKET, SO_ERROR, &err, &l);
    op->result = -err; // 0 on success
    completed.push_back(op);
    return true;
  }
  case IoOp::Type::Close:
    return true; // handled inline in submit()
  }

  if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    return false; // spurious wakeup: leave the op armed, retry next time
  }
  op->result = (r >= 0) ? static_cast<int>(r) : -errno;
  completed.push_back(op);
  return true;
}

void
EpollBackend::poll(int timeout_ms, std::vector<IoOp *> &completed)
{
  // Surface inline completions (closes, cancels) first.
  if (!_ready.empty()) {
    completed.insert(completed.end(), _ready.begin(), _ready.end());
    _ready.clear();
    timeout_ms = 0; // don't block; we already have work
  }

  epoll_event evs[64];
  int         n = ::epoll_wait(_epfd, evs, 64, timeout_ms);
  for (int i = 0; i < n; ++i) {
    int  fd = evs[i].data.fd;
    auto it = _fds.find(fd);
    if (it == _fds.end()) {
      continue;
    }
    uint32_t e = evs[i].events;

    // Treat error/hangup as readiness on whichever direction is armed so the
    // syscall runs and surfaces the real errno. perform() never erases the
    // FdState (only rearm() does), so the iterator stays valid here.
    if (it->second.read && (e & (EPOLLIN | EPOLLERR | EPOLLHUP))) {
      if (perform(it->second.read, completed)) {
        it->second.read = nullptr;
      }
    }
    if (it->second.write && (e & (EPOLLOUT | EPOLLERR | EPOLLHUP))) {
      if (perform(it->second.write, completed)) {
        it->second.write = nullptr;
      }
    }
    rearm(fd, it->second); // reconciles interest; may erase the FdState
  }
}

} // namespace coronet
