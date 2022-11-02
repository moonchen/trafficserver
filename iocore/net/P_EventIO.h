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

#pragma once
#include "tscore/ink_config.h"
#include "tscore/ink_apidefs.h"
#include "tscore/ink_assert.h"
#include "P_UnixPollDescriptor.h"

#define USE_EDGE_TRIGGER_EPOLL 1
#define USE_EDGE_TRIGGER_KQUEUE 1
#define USE_EDGE_TRIGGER_PORT 1

#if TS_USE_EPOLL
#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE 0
#endif
#ifdef USE_EDGE_TRIGGER_EPOLL
#define USE_EDGE_TRIGGER 1
#define EVENTIO_READ (EPOLLIN | EPOLLET)
#define EVENTIO_WRITE (EPOLLOUT | EPOLLET)
#else
#define EVENTIO_READ EPOLLIN
#define EVENTIO_WRITE EPOLLOUT
#endif
#define EVENTIO_ERROR (EPOLLERR | EPOLLPRI | EPOLLHUP)
#endif

#if TS_USE_KQUEUE
#ifdef USE_EDGE_TRIGGER_KQUEUE
#define USE_EDGE_TRIGGER 1
#define INK_EV_EDGE_TRIGGER EV_CLEAR
#else
#define INK_EV_EDGE_TRIGGER 0
#endif
#define EVENTIO_READ INK_EVP_IN
#define EVENTIO_WRITE INK_EVP_OUT
#define EVENTIO_ERROR (0x010 | 0x002 | 0x020) // ERR PRI HUP
#endif
#if TS_USE_PORT
#ifdef USE_EDGE_TRIGGER_PORT
#define USE_EDGE_TRIGGER 1
#endif
#define EVENTIO_READ POLLIN
#define EVENTIO_WRITE POLLOUT
#define EVENTIO_ERROR (POLLERR | POLLPRI | POLLHUP)
#endif

using EventLoop = PollDescriptor *;
class EventIOUser;

/// Unified API for setting and clearing kernel and epoll events.
struct EventIO {
  int fd = -1; ///< file descriptor, often a system port
#if TS_USE_KQUEUE || TS_USE_EPOLL && !defined(USE_EDGE_TRIGGER) || TS_USE_PORT
  int events = 0; ///< a bit mask of enabled events
#endif
  EventLoop event_loop = nullptr; ///< the assigned event loop
  bool syscall         = true;    ///< if false, disable all functionality (for QUIC)
  int type             = 0;       ///< class identifier of union data.
  EventIOUser *_user   = nullptr; ///< A continuation with a file descriptor

  enum eventIO_types {
    EVENTIO_NETACCEPT      = 1,
    EVENTIO_READWRITE_VC   = 2,
    EVENTIO_DNS_CONNECTION = 3,
    EVENTIO_UDP_CONNECTION = 4,
    EVENTIO_ASYNC_SIGNAL   = 5,
    EVENTIO_IO_URING       = 6
  };

  /** The start methods all logically Setup a class to be called
     when a file descriptor is available for read or write.
     The type of the classes vary.  Generally the file descriptor
     is pulled from the class, but there is one option that lets
     the file descriptor be expressed directly.
     @param l the event loop
     @param events a mask of flags (for details `man epoll_ctl`)
     @return int the number of events created, -1 is error
   */
  int start(EventLoop l, EventIOUser *user, int events);
  int start(EventLoop l, int afd, EventIOUser *user, int e);
  int start_common(EventLoop l, int fd, int events);

  /** Alter the events that will trigger the continuation, for level triggered I/O.
     @param events add with positive mask(+EVENTIO_READ), or remove with negative mask (-EVENTIO_READ)
     @return int the number of events created, -1 is error
   */
  int modify(int events);

  /** Refresh the existing events (i.e. KQUEUE EV_CLEAR), for edge triggered I/O
     @param events mask of events
     @return int the number of events created, -1 is error
   */
  int refresh(int events);

  /// Remove the kernel or epoll event. Returns 0 on success.
  int stop();

  /// Remove the epoll event and close the connection. Returns 0 on success.
  int close();

  EventIO() {}
};

class EventIOUser
{
public:
  virtual int get_fd()                          = 0;
  virtual EventIO::eventIO_types eventIO_type() = 0;
  virtual int eventIO_close()                   = 0;
};

TS_INLINE int
EventIO::start(EventLoop l, EventIOUser *user, int events)
{
  type  = user->eventIO_type();
  _user = user;
  return start_common(l, user->get_fd(), events);
}

TS_INLINE int
EventIO::start(EventLoop l, int afd, EventIOUser *ne, int e)
{
  _user = ne;
  return start_common(l, afd, e);
}

TS_INLINE int
EventIO::close()
{
  if (!this->syscall) {
    return 0;
  }

  stop();
  switch (type) {
  default:
    ink_assert(!"case");
  // fallthrough
  case EVENTIO_DNS_CONNECTION:
  case EVENTIO_NETACCEPT:
  case EVENTIO_READWRITE_VC:
    return _user->eventIO_close();
  }
  return -1;
}

TS_INLINE int
EventIO::start_common(EventLoop l, int afd, int e)
{
  if (!this->syscall) {
    return 0;
  }

  fd         = afd;
  event_loop = l;
#if TS_USE_EPOLL
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events   = e | EPOLLEXCLUSIVE;
  ev.data.ptr = this;
#ifndef USE_EDGE_TRIGGER
  events = e;
#endif
  return epoll_ctl(event_loop->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
#endif
#if TS_USE_KQUEUE
  events = e;
  struct kevent ev[2];
  int n = 0;
  if (e & EVENTIO_READ)
    EV_SET(&ev[n++], fd, EVFILT_READ, EV_ADD | INK_EV_EDGE_TRIGGER, 0, 0, this);
  if (e & EVENTIO_WRITE)
    EV_SET(&ev[n++], fd, EVFILT_WRITE, EV_ADD | INK_EV_EDGE_TRIGGER, 0, 0, this);
  return kevent(l->kqueue_fd, &ev[0], n, nullptr, 0, nullptr);
#endif
#if TS_USE_PORT
  events     = e;
  int retval = port_associate(event_loop->port_fd, PORT_SOURCE_FD, fd, events, this);
  Debug("iocore_eventio", "[EventIO::start] e(%d), events(%d), %d[%s]=port_associate(%d,%d,%d,%d,%p)", e, events, retval,
        retval < 0 ? strerror(errno) : "ok", event_loop->port_fd, PORT_SOURCE_FD, fd, events, this);
  return retval;
#endif
}

TS_INLINE int
EventIO::modify(int e)
{
  if (!this->syscall) {
    return 0;
  }

  ink_assert(event_loop);
#if TS_USE_EPOLL && !defined(USE_EDGE_TRIGGER)
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  int new_events = events, old_events = events;
  if (e < 0)
    new_events &= ~(-e);
  else
    new_events |= e;
  events      = new_events;
  ev.events   = new_events;
  ev.data.ptr = this;
  if (!new_events)
    return epoll_ctl(event_loop->epoll_fd, EPOLL_CTL_DEL, fd, &ev);
  else if (!old_events)
    return epoll_ctl(event_loop->epoll_fd, EPOLL_CTL_ADD, fd, &ev);
  else
    return epoll_ctl(event_loop->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
#endif
#if TS_USE_KQUEUE && !defined(USE_EDGE_TRIGGER)
  int n = 0;
  struct kevent ev[2];
  int ee = events;
  if (e < 0) {
    ee &= ~(-e);
    if ((-e) & EVENTIO_READ)
      EV_SET(&ev[n++], fd, EVFILT_READ, EV_DELETE, 0, 0, this);
    if ((-e) & EVENTIO_WRITE)
      EV_SET(&ev[n++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, this);
  } else {
    ee |= e;
    if (e & EVENTIO_READ)
      EV_SET(&ev[n++], fd, EVFILT_READ, EV_ADD | INK_EV_EDGE_TRIGGER, 0, 0, this);
    if (e & EVENTIO_WRITE)
      EV_SET(&ev[n++], fd, EVFILT_WRITE, EV_ADD | INK_EV_EDGE_TRIGGER, 0, 0, this);
  }
  events = ee;
  if (n)
    return kevent(event_loop->kqueue_fd, &ev[0], n, nullptr, 0, nullptr);
  else
    return 0;
#endif
#if TS_USE_PORT
  int n  = 0;
  int ne = e;
  if (e < 0) {
    if (((-e) & events)) {
      ne = ~(-e) & events;
      if ((-e) & EVENTIO_READ)
        n++;
      if ((-e) & EVENTIO_WRITE)
        n++;
    }
  } else {
    if (!(e & events)) {
      ne = events | e;
      if (e & EVENTIO_READ)
        n++;
      if (e & EVENTIO_WRITE)
        n++;
    }
  }
  if (n && ne && event_loop) {
    events     = ne;
    int retval = port_associate(event_loop->port_fd, PORT_SOURCE_FD, fd, events, this);
    Debug("iocore_eventio", "[EventIO::modify] e(%d), ne(%d), events(%d), %d[%s]=port_associate(%d,%d,%d,%d,%p)", e, ne, events,
          retval, retval < 0 ? strerror(errno) : "ok", event_loop->port_fd, PORT_SOURCE_FD, fd, events, this);
    return retval;
  }
  return 0;
#else
  (void)e; // ATS_UNUSED
  return 0;
#endif
}

TS_INLINE int
EventIO::refresh(int e)
{
  if (!this->syscall) {
    return 0;
  }

  ink_assert(event_loop);
#if TS_USE_KQUEUE && defined(USE_EDGE_TRIGGER)
  e = e & events;
  struct kevent ev[2];
  int n = 0;
  if (e & EVENTIO_READ)
    EV_SET(&ev[n++], fd, EVFILT_READ, EV_ADD | INK_EV_EDGE_TRIGGER, 0, 0, this);
  if (e & EVENTIO_WRITE)
    EV_SET(&ev[n++], fd, EVFILT_WRITE, EV_ADD | INK_EV_EDGE_TRIGGER, 0, 0, this);
  if (n)
    return kevent(event_loop->kqueue_fd, &ev[0], n, nullptr, 0, nullptr);
  else
    return 0;
#endif
#if TS_USE_PORT
  int n  = 0;
  int ne = e;
  if ((e & events)) {
    ne = events | e;
    if (e & EVENTIO_READ)
      n++;
    if (e & EVENTIO_WRITE)
      n++;
    if (n && ne && event_loop) {
      events     = ne;
      int retval = port_associate(event_loop->port_fd, PORT_SOURCE_FD, fd, events, this);
      Debug("iocore_eventio", "[EventIO::refresh] e(%d), ne(%d), events(%d), %d[%s]=port_associate(%d,%d,%d,%d,%p)", e, ne, events,
            retval, retval < 0 ? strerror(errno) : "ok", event_loop->port_fd, PORT_SOURCE_FD, fd, events, this);
      return retval;
    }
  }
  return 0;
#else
  (void)e; // ATS_UNUSED
  return 0;
#endif
}

TS_INLINE int
EventIO::stop()
{
  if (!this->syscall) {
    return 0;
  }
  if (event_loop) {
    int retval = 0;
#if TS_USE_EPOLL
    struct epoll_event ev;
    memset(&ev, 0, sizeof(struct epoll_event));
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    retval    = epoll_ctl(event_loop->epoll_fd, EPOLL_CTL_DEL, fd, &ev);
#endif
#if TS_USE_PORT
    retval = port_dissociate(event_loop->port_fd, PORT_SOURCE_FD, fd);
    Debug("iocore_eventio", "[EventIO::stop] %d[%s]=port_dissociate(%d,%d,%d)", retval, retval < 0 ? strerror(errno) : "ok",
          event_loop->port_fd, PORT_SOURCE_FD, fd);
#endif
    event_loop = nullptr;
    return retval;
  }
  return 0;
}
