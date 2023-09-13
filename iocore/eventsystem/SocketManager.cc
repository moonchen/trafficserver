/** @file

  A brief file description

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

/****************************************************************************

  SocketManager.cc
 ****************************************************************************/
#include "tscore/ink_platform.h"
#include "P_EventSystem.h"

#include "tscore/TextBuffer.h"
#include "tscore/ink_sock.h"

//
// These limits are currently disabled
//
// 1024 - stdin, stderr, stdout
#define EPOLL_MAX_DESCRIPTOR_SIZE 32768

bool
transient_error()
{
  bool transient = (errno == EINTR);
#ifdef ENOMEM
  transient = transient || (errno == ENOMEM);
#endif
#ifdef ENOBUFS
  transient = transient || (errno == ENOBUFS);
#endif
  return transient;
}

int
SocketManager::open(const char *path, int oflag, mode_t mode)
{
  int s;
  do {
    s = ::open(path, oflag, mode);
    if (likely(s >= 0)) {
      break;
    }
    s = -errno;
  } while (transient_error());
  return s;
}

int64_t
SocketManager::read(int fd, void *buf, int size, void * /* pOLP ATS_UNUSED */)
{
  int64_t r;
  do {
    r = ::read(fd, buf, size);
    if (likely(r >= 0)) {
      break;
    }
    r = -errno;
  } while (r == -EINTR);
  return r;
}

int
SocketManager::recv(int fd, void *buf, int size, int flags)
{
  int r;
  do {
    if (unlikely((r = ::recv(fd, (char *)buf, size, flags)) < 0)) {
      r = -errno;
    }
  } while (r == -EINTR);
  return r;
}

int
SocketManager::recvfrom(int fd, void *buf, int size, int flags, struct sockaddr *addr, socklen_t *addrlen)
{
  int r;
  do {
    r = ::recvfrom(fd, static_cast<char *>(buf), size, flags, addr, addrlen);
    if (unlikely(r < 0)) {
      r = -errno;
    }
  } while (r == -EINTR);
  return r;
}

int
SocketManager::recvmsg(int fd, struct msghdr *m, int flags, void * /* pOLP ATS_UNUSED */)
{
  int r;
  do {
    if (unlikely((r = ::recvmsg(fd, m, flags)) < 0)) {
      r = -errno;
    }
  } while (r == -EINTR);
  return r;
}

#ifdef HAVE_RECVMMSG
int
SocketManager::recvmmsg(int fd, struct mmsghdr *msgvec, int vlen, int flags, struct timespec *timeout, void * /* pOLP ATS_UNUSED */)
{
  int r;
  do {
    if (unlikely((r = ::recvmmsg(fd, msgvec, vlen, flags, timeout)) < 0)) {
      r = -errno;
      // EINVAL can ocur if timeout is invalid.
    }
  } while (r == -EINTR);
  return r;
}
#endif

int64_t
SocketManager::write(int fd, void *buf, int size, void * /* pOLP ATS_UNUSED */)
{
  int64_t r;
  do {
    if (likely((r = ::write(fd, buf, size)) >= 0)) {
      break;
    }
    r = -errno;
  } while (r == -EINTR);
  return r;
}

int64_t
SocketManager::pwrite(int fd, void *buf, int size, off_t offset, char * /* tag ATS_UNUSED */)
{
  int64_t r;
  do {
    if (unlikely((r = ::pwrite(fd, buf, size, offset)) < 0)) {
      r = -errno;
    }
  } while (r == -EINTR);
  return r;
}

int
SocketManager::send(int fd, void *buf, int size, int flags)
{
  int r;
  do {
    if (unlikely((r = ::send(fd, (char *)buf, size, flags)) < 0)) {
      r = -errno;
    }
  } while (r == -EINTR);
  return r;
}

int
SocketManager::sendto(int fd, void *buf, int len, int flags, struct sockaddr const *to, int tolen)
{
  int r;
  do {
    if (unlikely((r = ::sendto(fd, (char *)buf, len, flags, to, tolen)) < 0)) {
      r = -errno;
    }
  } while (r == -EINTR);
  return r;
}

int
SocketManager::sendmsg(int fd, struct msghdr *m, int flags, void * /* pOLP ATS_UNUSED */)
{
  int r;
  do {
    if (unlikely((r = ::sendmsg(fd, m, flags)) < 0)) {
      r = -errno;
    }
  } while (r == -EINTR);
  return r;
}

int64_t
SocketManager::lseek(int fd, off_t offset, int whence)
{
  int64_t r;
  do {
    if ((r = ::lseek(fd, offset, whence)) < 0) {
      r = -errno;
    }
  } while (r == -EINTR);
  return r;
}

int
SocketManager::fsync(int fildes)
{
  int r;
  do {
    if ((r = ::fsync(fildes)) < 0) {
      r = -errno;
    }
  } while (r == -EINTR);
  return r;
}

int
SocketManager::poll(struct pollfd *fds, unsigned long nfds, int timeout)
{
  int r;
  do {
    if ((r = ::poll(fds, nfds, timeout)) >= 0) {
      break;
    }
    r = -errno;
  } while (transient_error());
  return r;
}

int
SocketManager::get_sndbuf_size(int s)
{
  int bsz = 0;
  int bszsz, r;

  bszsz = sizeof(bsz);
  r     = safe_getsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char *>(&bsz), &bszsz);
  return (r == 0 ? bsz : r);
}

int
SocketManager::get_rcvbuf_size(int s)
{
  int bsz = 0;
  int bszsz, r;

  bszsz = sizeof(bsz);
  r     = safe_getsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char *>(&bsz), &bszsz);
  return (r == 0 ? bsz : r);
}

int
SocketManager::set_sndbuf_size(int s, int bsz)
{
  return safe_setsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char *>(&bsz), sizeof(bsz));
}

int
SocketManager::set_rcvbuf_size(int s, int bsz)
{
  return safe_setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char *>(&bsz), sizeof(bsz));
}

int
SocketManager::getsockname(int s, struct sockaddr *sa, socklen_t *sz)
{
  return ::getsockname(s, sa, sz);
}

int
SocketManager::socket(int domain, int type, int protocol)
{
  return ::socket(domain, type, protocol);
}

int
SocketManager::shutdown(int s, int how)
{
  int res;
  do {
    if (unlikely((res = ::shutdown(s, how)) < 0)) {
      res = -errno;
    }
  } while (res == -EINTR);
  return res;
}

#if !HAVE_ACCEPT4
static int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
  int fd, err;

  do {
    fd = accept(sockfd, addr, addrlen);
    if (likely(fd >= 0)) {
      break;
    }
  } while (transient_error());

  if ((fd >= 0) && (flags & SOCK_CLOEXEC) && (safe_fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)) {
    err = errno;
    close(fd);
    errno = err;
    return -1;
  }

  if ((fd >= 0) && (flags & SOCK_NONBLOCK) && (safe_nonblocking(fd) < 0)) {
    err = errno;
    close(fd);
    errno = err;
    return -1;
  }

  return fd;
}
#endif

int
SocketManager::accept4(int s, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
  do {
    int fd = ::accept4(s, addr, addrlen, flags);
    if (likely(fd >= 0)) {
      return fd;
    }
  } while (transient_error());

  return -errno;
}

int
SocketManager::ink_bind(int s, struct sockaddr const *name, int namelen, short Proto)
{
  (void)Proto;
  return safe_bind(s, name, namelen);
}

int
SocketManager::close(int s)
{
  int res;

  if (s == 0) {
    return -EACCES;
  } else if (s < 0) {
    return -EINVAL;
  }

  do {
    res = ::close(s);
    if (res == -1) {
      res = -errno;
    }
  } while (res == -EINTR);
  return res;
}

bool
SocketManager::fastopen_supported()
{
  static const unsigned TFO_CLIENT_ENABLE = 1;

  ats_scoped_fd fd(::open("/proc/sys/net/ipv4/tcp_fastopen", O_RDONLY));
  int value = 0;

  if (fd.isValid()) {
    TextBuffer buffer(16);

    buffer.slurp(fd.get());
    value = atoi(buffer.bufPtr());
  }

  return value & TFO_CLIENT_ENABLE;
}
