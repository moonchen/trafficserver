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

  UnixUDPNet.cc
  UDPNet implementation


 ****************************************************************************/

#if defined(darwin)
/* This is for IPV6_PKTINFO and IPV6_RECVPKTINFO */
#define __APPLE_USE_RFC_3542
#endif

#include "P_Net.h"
#include "P_UnixNet.h"
#include "P_UDPNet.h"
#include "I_AIO.h"
#include "tscore/ink_sock.h"

#include "netinet/udp.h"
#ifndef UDP_SEGMENT
// This is needed because old glibc may not have the constant even if Kernel supports it.
#define UDP_SEGMENT 103
#endif

using UDPNetContHandler = int (UDPNetHandler::*)(int, void *);

ClassAllocator<UDPPacketInternal> udpPacketAllocator("udpPacketAllocator");
EventType ET_UDP;

void
UDPPacketInternal::free()
{
  chain = nullptr;
  if (conn)
    conn->Release();
  conn = nullptr;
  udpPacketAllocator.free(this);
}

UDPPacket *
UDPPacket::new_UDPPacket()
{
  UDPPacketInternal *p = udpPacketAllocator.alloc();
  return p;
}

UDPPacket *
UDPPacket::new_UDPPacket(struct sockaddr const *to, ink_hrtime when, Ptr<IOBufferBlock> &buf, uint16_t segment_size)
{
  UDPPacketInternal *p = udpPacketAllocator.alloc();

  p->in_the_priority_queue = 0;
  p->in_heap               = 0;
  p->delivery_time         = when;
  if (to)
    ats_ip_copy(&p->to, to);
  p->chain        = buf;
  p->segment_size = segment_size;
  return p;
}

UDPPacket *
UDPPacket::new_incoming_UDPPacket(struct sockaddr *from, struct sockaddr *to, Ptr<IOBufferBlock> &block)
{
  UDPPacketInternal *p = udpPacketAllocator.alloc();

  p->in_the_priority_queue = 0;
  p->in_heap               = 0;
  p->delivery_time         = 0;
  ats_ip_copy(&p->from, from);
  ats_ip_copy(&p->to, to);
  p->chain = block;

  return p;
}

UDPPacketInternal::UDPPacketInternal()

{
  memset(&from, '\0', sizeof(from));
  memset(&to, '\0', sizeof(to));
}

UDPPacketInternal::~UDPPacketInternal()
{
  chain = nullptr;
}

void
UDPPacket::append_block(IOBufferBlock *block)
{
  UDPPacketInternal *p = static_cast<UDPPacketInternal *>(this);

  if (block) {
    if (p->chain) { // append to end
      IOBufferBlock *last = p->chain.get();
      while (last->next) {
        last = last->next.get();
      }
      last->next = block;
    } else {
      p->chain = block;
    }
  }
}

int64_t
UDPPacket::getPktLength() const
{
  UDPPacketInternal *p = const_cast<UDPPacketInternal *>(static_cast<const UDPPacketInternal *>(this));
  IOBufferBlock *b;

  p->pktLength = 0;
  b            = p->chain.get();
  while (b) {
    p->pktLength += b->read_avail();
    b            = b->next.get();
  }
  return p->pktLength;
}

void
UDPPacket::free()
{
  static_cast<UDPPacketInternal *>(this)->free();
}

void
UDPPacket::setContinuation(Continuation *c)
{
  static_cast<UDPPacketInternal *>(this)->cont = c;
}

void
UDPPacket::setConnection(UDPConnection *c)
{
  /*Code reviewed by Case Larsen.  Previously, we just had
     ink_assert(!conn).  This prevents tunneling of packets
     correctly---that is, you get packets from a server on a udp
     conn. and want to send it to a player on another connection, the
     assert will prevent that.  The "if" clause enables correct
     handling of the connection ref. counts in such a scenario. */

  UDPConnectionInternal *&conn = static_cast<UDPPacketInternal *>(this)->conn;

  if (conn) {
    if (conn == c)
      return;
    conn->Release();
    conn = nullptr;
  }
  conn = static_cast<UDPConnectionInternal *>(c);
  conn->AddRef();
}

IOBufferBlock *
UDPPacket::getIOBlockChain()
{
  ink_assert(dynamic_cast<UDPPacketInternal *>(this) != nullptr);
  return static_cast<UDPPacketInternal *>(this)->chain.get();
}

UDPConnection *
UDPPacket::getConnection()
{
  return static_cast<UDPPacketInternal *>(this)->conn;
}

//
// Global Data
//

UDPNetProcessorInternal udpNetInternal;
UDPNetProcessor &udpNet = udpNetInternal;

int32_t g_udp_periodicCleanupSlots;
int32_t g_udp_periodicFreeCancelledPkts;
int32_t g_udp_numSendRetries;

//
// Public functions
// See header for documentation
//
int G_bwGrapherFd;
sockaddr_in6 G_bwGrapherLoc;

void
initialize_thread_for_udp_net(EThread *thread)
{
  int enable_gso;
  REC_ReadConfigInteger(enable_gso, "proxy.config.udp.enable_gso");

  UDPNetHandler *nh = get_UDPNetHandler(thread);

  new (reinterpret_cast<ink_dummy_for_new *>(nh)) UDPNetHandler(enable_gso);
  new (reinterpret_cast<ink_dummy_for_new *>(get_UDPPollCont(thread))) PollCont(thread->mutex);
  // The UDPNetHandler cannot be accessed across EThreads.
  // Because the UDPNetHandler should be called back immediately after UDPPollCont.
  nh->mutex  = thread->mutex.get();
  nh->thread = thread;

  PollCont *upc       = get_UDPPollCont(thread);
  PollDescriptor *upd = upc->pollDescriptor;
  // due to ET_UDP is really simple, it should sleep for a long time
  // TODO: fixed size
  upc->poll_timeout = 100;
  // This variable controls how often we cleanup the cancelled packets.
  // If it is set to 0, then cleanup never occurs.
  REC_ReadConfigInt32(g_udp_periodicFreeCancelledPkts, "proxy.config.udp.free_cancelled_pkts_sec");

  // This variable controls how many "slots" of the udp calendar queue we cleanup.
  // If it is set to 0, then cleanup never occurs.  This value makes sense
  // only if the above variable is set.
  REC_ReadConfigInt32(g_udp_periodicCleanupSlots, "proxy.config.udp.periodic_cleanup");

  // UDP sends can fail with errno=EAGAIN.  This variable determines the # of
  // times the UDP thread retries before giving up.  Set to 0 to keep trying forever.
  REC_ReadConfigInt32(g_udp_numSendRetries, "proxy.config.udp.send_retries");
  g_udp_numSendRetries = g_udp_numSendRetries < 0 ? 0 : g_udp_numSendRetries;

  thread->set_tail_handler(nh);
  thread->ep.emplace();
#if HAVE_EVENTFD
#if TS_USE_LINUX_IO_URING
  thread->ep->start(upd, DiskHandler::local_context());
#else
  thread->ep->start(upd, thread->evfd, EVENTIO_READ);
#endif
#else
  thread->ep->start(upd, thread->evpipe[0], EVENTIO_READ);
#endif
}

EventType
UDPNetProcessorInternal::register_event_type()
{
  ET_UDP = eventProcessor.register_event_type("ET_UDP");
  return ET_UDP;
}

int
UDPNetProcessorInternal::start(int n_upd_threads, size_t stacksize)
{
  if (n_upd_threads < 1) {
    return -1;
  }

  pollCont_offset      = eventProcessor.allocate(sizeof(PollCont));
  udpNetHandler_offset = eventProcessor.allocate(sizeof(UDPNetHandler));

  eventProcessor.schedule_spawn(&initialize_thread_for_udp_net, ET_UDP);
  eventProcessor.spawn_event_threads(ET_UDP, n_upd_threads, stacksize);

  return 0;
}

void
UDPNetProcessorInternal::udp_read_from_net(UDPNetHandler *nh, UDPConnection *xuc)
{
  UnixUDPConnection *uc = (UnixUDPConnection *)xuc;

  // receive packet and queue onto UDPConnection.
  // don't call back connection at this time.
  int64_t r;
  int iters         = 0;
  unsigned max_niov = 32;

  struct msghdr msg;
  Ptr<IOBufferBlock> chain, next_chain;
  struct iovec tiovec[max_niov];
  int64_t size_index  = BUFFER_SIZE_INDEX_2K;
  int64_t buffer_size = BUFFER_SIZE_FOR_INDEX(size_index);
  // The max length of receive buffer is 32 * buffer_size (2048) = 65536 bytes.
  // Because the 'UDP Length' is type of uint16_t defined in RFC 768.
  // And there is 8 octets in 'User Datagram Header' which means the max length of payload is no more than 65527 bytes.
  do {
    // create IOBufferBlock chain to receive data
    unsigned int niov;
    IOBufferBlock *b, *last;

    // build struct iov
    // reuse the block in chain if available
    b    = chain.get();
    last = nullptr;
    for (niov = 0; niov < max_niov; niov++) {
      if (b == nullptr) {
        b = new_IOBufferBlock();
        b->alloc(size_index);
        if (last == nullptr) {
          chain = b;
        } else {
          last->next = b;
        }
      }

      tiovec[niov].iov_base = b->buf();
      tiovec[niov].iov_len  = b->block_size();

      last = b;
      b    = b->next.get();
    }

    // build struct msghdr
    sockaddr_in6 fromaddr;
    sockaddr_in6 toaddr;
    int toaddr_len = sizeof(toaddr);
    char *cbuf[1024];
    msg.msg_name       = &fromaddr;
    msg.msg_namelen    = sizeof(fromaddr);
    msg.msg_iov        = tiovec;
    msg.msg_iovlen     = niov;
    msg.msg_control    = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    // receive data by recvmsg
    r = SocketManager::recvmsg(uc->getFd(), &msg, 0);
    if (r <= 0) {
      // error
      break;
    }

    // truncated check
    if (msg.msg_flags & MSG_TRUNC) {
      Debug("udp-read", "The UDP packet is truncated");
    }

    // fill the IOBufferBlock chain
    int64_t saved = r;
    b             = chain.get();
    while (b && saved > 0) {
      if (saved > buffer_size) {
        b->fill(buffer_size);
        saved -= buffer_size;
        b     = b->next.get();
      } else {
        b->fill(saved);
        saved      = 0;
        next_chain = b->next.get();
        b->next    = nullptr;
      }
    }

    safe_getsockname(xuc->getFd(), reinterpret_cast<struct sockaddr *>(&toaddr), &toaddr_len);
    for (auto cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
      switch (cmsg->cmsg_type) {
#ifdef IP_PKTINFO
      case IP_PKTINFO:
        if (cmsg->cmsg_level == IPPROTO_IP) {
          struct in_pktinfo *pktinfo                                = reinterpret_cast<struct in_pktinfo *>(CMSG_DATA(cmsg));
          reinterpret_cast<sockaddr_in *>(&toaddr)->sin_addr.s_addr = pktinfo->ipi_addr.s_addr;
        }
        break;
#endif
#ifdef IP_RECVDSTADDR
      case IP_RECVDSTADDR:
        if (cmsg->cmsg_level == IPPROTO_IP) {
          struct in_addr *addr                                      = reinterpret_cast<struct in_addr *>(CMSG_DATA(cmsg));
          reinterpret_cast<sockaddr_in *>(&toaddr)->sin_addr.s_addr = addr->s_addr;
        }
        break;
#endif
#if defined(IPV6_PKTINFO) || defined(IPV6_RECVPKTINFO)
      case IPV6_PKTINFO: // IPV6_RECVPKTINFO uses IPV6_PKTINFO too
        if (cmsg->cmsg_level == IPPROTO_IPV6) {
          struct in6_pktinfo *pktinfo = reinterpret_cast<struct in6_pktinfo *>(CMSG_DATA(cmsg));
          memcpy(toaddr.sin6_addr.s6_addr, &pktinfo->ipi6_addr, 16);
        }
        break;
#endif
      }
    }

    // create packet
    UDPPacket *p = UDPPacket::new_incoming_UDPPacket(ats_ip_sa_cast(&fromaddr), ats_ip_sa_cast(&toaddr), chain);
    p->setConnection(uc);
    // queue onto the UDPConnection
    uc->inQueue.push((UDPPacketInternal *)p);

    // reload the unused block
    chain      = next_chain;
    next_chain = nullptr;
    iters++;
  } while (r > 0);
  if (iters >= 1) {
    Debug("udp-read", "read %d at a time", iters);
  }
  // if not already on to-be-called-back queue, then add it.
  if (!uc->onCallbackQueue) {
    ink_assert(uc->callback_link.next == nullptr);
    ink_assert(uc->callback_link.prev == nullptr);
    uc->AddRef();
    nh->udp_callbacks.enqueue(uc);
    uc->onCallbackQueue = 1;
  }
}

int
UDPNetProcessorInternal::udp_callback(UDPNetHandler *nh, UDPConnection *xuc, EThread *thread)
{
  (void)nh;
  UnixUDPConnection *uc = (UnixUDPConnection *)xuc;

  if (uc->continuation && uc->mutex) {
    MUTEX_TRY_LOCK(lock, uc->mutex, thread);
    if (!lock.is_locked()) {
      return 1;
    }
    uc->AddRef();
    uc->callbackHandler(0, nullptr);
    return 0;
  } else {
    ink_assert(!"doesn't reach here");
    if (!uc->callbackAction) {
      uc->AddRef();
      uc->callbackAction = eventProcessor.schedule_imm(uc);
    }
    return 0;
  }
}

#define UNINITIALIZED_EVENT_PTR (Event *)0xdeadbeef

// cheesy implementation of a asynchronous read and callback for Unix
class UDPReadContinuation : public Continuation
{
public:
  UDPReadContinuation(Event *completionToken);
  UDPReadContinuation();
  ~UDPReadContinuation() override;
  inline void free();
  inline void init_token(Event *completionToken);
  inline void init_read(int fd, IOBufferBlock *buf, int len, struct sockaddr *fromaddr, socklen_t *fromaddrlen);

  void
  set_timer(int seconds)
  {
    timeout_interval = HRTIME_SECONDS(seconds);
  }

  void cancel();
  int readPollEvent(int event, Event *e);

  Action *
  getAction()
  {
    return event;
  }

  void setupPollDescriptor();

private:
  Event *event = UNINITIALIZED_EVENT_PTR; // the completion event token created
  // on behalf of the client
  Ptr<IOBufferBlock> readbuf{nullptr};
  int readlen                   = 0;
  struct sockaddr_in6 *fromaddr = nullptr;
  socklen_t *fromaddrlen        = nullptr;
  int fd                        = NO_FD; // fd we are reading from
  int ifd                       = NO_FD; // poll fd index
  ink_hrtime period             = 0;     // polling period
  ink_hrtime elapsed_time       = 0;
  ink_hrtime timeout_interval   = 0;
};

ClassAllocator<UDPReadContinuation> udpReadContAllocator("udpReadContAllocator");

UDPReadContinuation::UDPReadContinuation(Event *completionToken)
  : Continuation(nullptr),
    event(completionToken),
    readbuf(nullptr),

    fd(-1),
    ifd(-1)

{
  if (completionToken->continuation) {
    this->mutex = completionToken->continuation->mutex;
  } else {
    this->mutex = new_ProxyMutex();
  }
}

UDPReadContinuation::UDPReadContinuation() : Continuation(nullptr) {}

inline void
UDPReadContinuation::free()
{
  ink_assert(event != nullptr);
  completionUtil::destroy(event);
  event            = nullptr;
  readbuf          = nullptr;
  readlen          = 0;
  fromaddrlen      = nullptr;
  fd               = -1;
  ifd              = -1;
  period           = 0;
  elapsed_time     = 0;
  timeout_interval = 0;
  mutex            = nullptr;
  udpReadContAllocator.free(this);
}

inline void
UDPReadContinuation::init_token(Event *completionToken)
{
  if (completionToken->continuation) {
    this->mutex = completionToken->continuation->mutex;
  } else {
    this->mutex = new_ProxyMutex();
  }
  event = completionToken;
}

inline void
UDPReadContinuation::init_read(int rfd, IOBufferBlock *buf, int len, struct sockaddr *fromaddr_, socklen_t *fromaddrlen_)
{
  ink_assert(rfd >= 0 && buf != nullptr && fromaddr_ != nullptr && fromaddrlen_ != nullptr);
  fd          = rfd;
  readbuf     = buf;
  readlen     = len;
  fromaddr    = ats_ip6_cast(fromaddr_);
  fromaddrlen = fromaddrlen_;
  SET_HANDLER(&UDPReadContinuation::readPollEvent);
  period = -HRTIME_MSECONDS(net_event_period);
  setupPollDescriptor();
  this_ethread()->schedule_every(this, period);
}

UDPReadContinuation::~UDPReadContinuation()
{
  if (event != UNINITIALIZED_EVENT_PTR) {
    ink_assert(event != nullptr);
    completionUtil::destroy(event);
    event = nullptr;
  }
}

void
UDPReadContinuation::cancel()
{
  // I don't think this actually cancels it correctly right now.
  event->cancel();
}

void
UDPReadContinuation::setupPollDescriptor()
{
#if TS_USE_EPOLL
  Pollfd *pfd;
  EThread *et  = (EThread *)this_thread();
  PollCont *pc = get_PollCont(et);
  if (pc->nextPollDescriptor == nullptr) {
    pc->nextPollDescriptor = new PollDescriptor();
  }
  pfd     = pc->nextPollDescriptor->alloc();
  pfd->fd = fd;
  ifd     = pfd - pc->nextPollDescriptor->pfd;
  ink_assert(pc->nextPollDescriptor->nfds > ifd);
  pfd->events  = POLLIN;
  pfd->revents = 0;
#endif
}

int
UDPReadContinuation::readPollEvent(int event_, Event *e)
{
  (void)event_;
  (void)e;

  // PollCont *pc = get_PollCont(e->ethread);
  Continuation *c;

  if (event->cancelled) {
    e->cancel();
    free();
    return EVENT_DONE;
  }

  // See if the request has timed out
  if (timeout_interval) {
    elapsed_time += -period;
    if (elapsed_time >= timeout_interval) {
      c = completionUtil::getContinuation(event);
      // TODO: Should we deal with the return code?
      c->handleEvent(NET_EVENT_DATAGRAM_READ_ERROR, event);
      e->cancel();
      free();
      return EVENT_DONE;
    }
  }

  c = completionUtil::getContinuation(event);
  // do read
  socklen_t tmp_fromlen = *fromaddrlen;
  int rlen              = SocketManager::recvfrom(fd, readbuf->end(), readlen, 0, ats_ip_sa_cast(fromaddr), &tmp_fromlen);

  completionUtil::setThread(event, e->ethread);
  // call back user with their event
  if (rlen > 0) {
    // do callback if read is successful
    *fromaddrlen = tmp_fromlen;
    completionUtil::setInfo(event, fd, readbuf, rlen, errno);
    readbuf->fill(rlen);
    // TODO: Should we deal with the return code?
    c->handleEvent(NET_EVENT_DATAGRAM_READ_COMPLETE, event);
    e->cancel();
    free();

    return EVENT_DONE;
  } else if (rlen < 0 && rlen != -EAGAIN) {
    // signal error.
    *fromaddrlen = tmp_fromlen;
    completionUtil::setInfo(event, fd, readbuf, rlen, errno);
    c = completionUtil::getContinuation(event);
    // TODO: Should we deal with the return code?
    c->handleEvent(NET_EVENT_DATAGRAM_READ_ERROR, event);
    e->cancel();
    free();

    return EVENT_DONE;
  } else {
    completionUtil::setThread(event, nullptr);
  }

  if (event->cancelled) {
    e->cancel();
    free();

    return EVENT_DONE;
  }
  // reestablish poll
  setupPollDescriptor();

  return EVENT_CONT;
}

/* recvfrom:
 * Unix:
 *   assert(buf->write_avail() >= len);
 *   *actual_len = recvfrom(fd,addr,buf->end(),len)
 *   if successful then
 *      buf->fill(*actual_len);
 *      return ACTION_RESULT_DONE
 *   else if nothing read
 *      *actual_len is 0
 *      create "UDP read continuation" C with 'cont's lock
 *         set user callback to 'cont'
 *      return C's action.
 *   else
 *      return error;
 */
Action *
UDPNetProcessor::recvfrom_re(Continuation *cont, void *token, int fd, struct sockaddr *fromaddr, socklen_t *fromaddrlen,
                             IOBufferBlock *buf, int len, bool useReadCont, int timeout)
{
  (void)useReadCont;
  ink_assert(buf->write_avail() >= len);
  int actual;
  Event *event = completionUtil::create();

  completionUtil::setContinuation(event, cont);
  completionUtil::setHandle(event, token);
  actual = SocketManager::recvfrom(fd, buf->end(), len, 0, fromaddr, fromaddrlen);

  if (actual > 0) {
    completionUtil::setThread(event, this_ethread());
    completionUtil::setInfo(event, fd, make_ptr(buf), actual, errno);
    buf->fill(actual);
    cont->handleEvent(NET_EVENT_DATAGRAM_READ_COMPLETE, event);
    completionUtil::destroy(event);
    return ACTION_RESULT_DONE;
  } else if (actual == 0 || actual == -EAGAIN) {
    UDPReadContinuation *c = udpReadContAllocator.alloc();
    c->init_token(event);
    c->init_read(fd, buf, len, fromaddr, fromaddrlen);
    if (timeout) {
      c->set_timer(timeout);
    }
    return event;
  } else {
    completionUtil::setThread(event, this_ethread());
    completionUtil::setInfo(event, fd, make_ptr(buf), actual, errno);
    cont->handleEvent(NET_EVENT_DATAGRAM_READ_ERROR, event);
    completionUtil::destroy(event);
    return ACTION_IO_ERROR;
  }
}

/* sendmsg:
 * Unix:
 *   *actual_len = sendmsg(fd,msg,default-flags);
 *   if successful,
 *      return ACTION_RESULT_DONE
 *   else
 *      return error
 */
Action *
UDPNetProcessor::sendmsg_re(Continuation *cont, void *token, int fd, struct msghdr *msg)
{
  int actual;
  Event *event = completionUtil::create();

  completionUtil::setContinuation(event, cont);
  completionUtil::setHandle(event, token);

  actual = SocketManager::sendmsg(fd, msg, 0);
  if (actual >= 0) {
    completionUtil::setThread(event, this_ethread());
    completionUtil::setInfo(event, fd, msg, actual, errno);
    cont->handleEvent(NET_EVENT_DATAGRAM_WRITE_COMPLETE, event);
    completionUtil::destroy(event);
    return ACTION_RESULT_DONE;
  } else {
    completionUtil::setThread(event, this_ethread());
    completionUtil::setInfo(event, fd, msg, actual, errno);
    cont->handleEvent(NET_EVENT_DATAGRAM_WRITE_ERROR, event);
    completionUtil::destroy(event);
    return ACTION_IO_ERROR;
  }
}

/* sendto:
 * If this were implemented, it might be implemented like this:
 * Unix:
 *   call sendto(fd,addr,buf->reader()->start(),len);
 *   if successful,
 *      buf->consume(len);
 *      return ACTION_RESULT_DONE
 *   else
 *      return error
 *
 */
Action *
UDPNetProcessor::sendto_re(Continuation *cont, void *token, int fd, struct sockaddr const *toaddr, int toaddrlen,
                           IOBufferBlock *buf, int len)
{
  (void)token;
  ink_assert(buf->read_avail() >= len);
  int nbytes_sent = SocketManager::sendto(fd, buf->start(), len, 0, toaddr, toaddrlen);

  if (nbytes_sent >= 0) {
    ink_assert(nbytes_sent == len);
    buf->consume(nbytes_sent);
    cont->handleEvent(NET_EVENT_DATAGRAM_WRITE_COMPLETE, (void *)-1);
    return ACTION_RESULT_DONE;
  } else {
    cont->handleEvent(NET_EVENT_DATAGRAM_WRITE_ERROR, (void *)static_cast<intptr_t>(nbytes_sent));
    return ACTION_IO_ERROR;
  }
}

bool
UDPNetProcessor::CreateUDPSocket(int *resfd, sockaddr const *remote_addr, Action **status, NetVCOptions &opt)
{
  int res = 0, fd = -1;
  int local_addr_len;
  IpEndpoint local_addr;

  // Need to do address calculations first, so we can determine the
  // address family for socket creation.
  ink_zero(local_addr);

  bool is_any_address = false;
  if (NetVCOptions::FOREIGN_ADDR == opt.addr_binding || NetVCOptions::INTF_ADDR == opt.addr_binding) {
    // Same for now, transparency for foreign addresses must be handled
    // *after* the socket is created, and we need to do this calculation
    // before the socket to get the IP family correct.
    ink_release_assert(opt.local_ip.isValid());
    local_addr.assign(opt.local_ip, htons(opt.local_port));
    ink_assert(ats_ip_are_compatible(remote_addr, &local_addr.sa));
  } else {
    // No local address specified, so use family option if possible.
    int family = ats_is_ip(opt.ip_family) ? opt.ip_family : AF_INET;
    local_addr.setToAnyAddr(family);
    is_any_address                  = true;
    local_addr.network_order_port() = htons(opt.local_port);
  }

  *resfd = -1;
  if ((res = SocketManager::socket(remote_addr->sa_family, SOCK_DGRAM, 0)) < 0) {
    goto HardError;
  }

  fd = res;
  if (safe_fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
    goto HardError;
  }

  if (opt.socket_recv_bufsize > 0) {
    if (unlikely(SocketManager::set_rcvbuf_size(fd, opt.socket_recv_bufsize))) {
      Debug("udpnet", "set_dnsbuf_size(%d) failed", opt.socket_recv_bufsize);
    }
  }
  if (opt.socket_send_bufsize > 0) {
    if (unlikely(SocketManager::set_sndbuf_size(fd, opt.socket_send_bufsize))) {
      Debug("udpnet", "set_dnsbuf_size(%d) failed", opt.socket_send_bufsize);
    }
  }

  if (opt.ip_family == AF_INET) {
    bool succeeded = false;
    int enable     = 1;
#ifdef IP_PKTINFO
    if (safe_setsockopt(fd, IPPROTO_IP, IP_PKTINFO, reinterpret_cast<char *>(&enable), sizeof(enable)) == 0) {
      succeeded = true;
    }
#endif
#ifdef IP_RECVDSTADDR
    if (safe_setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, reinterpret_cast<char *>(&enable), sizeof(enable)) == 0) {
      succeeded = true;
    }
#endif
    if (!succeeded) {
      Debug("udpnet", "setsockeopt for pktinfo failed");
      goto HardError;
    }
  } else if (opt.ip_family == AF_INET6) {
    bool succeeded = false;
    int enable     = 1;
#ifdef IPV6_PKTINFO
    if (safe_setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, reinterpret_cast<char *>(&enable), sizeof(enable)) == 0) {
      succeeded = true;
    }
#endif
#ifdef IPV6_RECVPKTINFO
    if (safe_setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, reinterpret_cast<char *>(&enable), sizeof(enable)) == 0) {
      succeeded = true;
    }
#endif
    if (!succeeded) {
      Debug("udpnet", "setsockeopt for pktinfo failed");
      goto HardError;
    }
  }

  if (local_addr.network_order_port() || !is_any_address) {
    if (-1 == SocketManager::ink_bind(fd, &local_addr.sa, ats_ip_size(&local_addr.sa))) {
      char buff[INET6_ADDRPORTSTRLEN];
      Debug("udpnet", "ink bind failed on %s", ats_ip_nptop(local_addr, buff, sizeof(buff)));
      goto SoftError;
    }

    if (safe_getsockname(fd, &local_addr.sa, &local_addr_len) < 0) {
      Debug("udpnet", "CreateUdpsocket: getsockname didn't work");
      goto HardError;
    }
  }

  *resfd  = fd;
  *status = nullptr;
  Debug("udpnet", "creating a udp socket port = %d, %d---success", ats_ip_port_host_order(remote_addr),
        ats_ip_port_host_order(local_addr));
  return true;
SoftError:
  Debug("udpnet", "creating a udp socket port = %d---soft failure", ats_ip_port_host_order(local_addr));
  if (fd != -1) {
    SocketManager::close(fd);
  }
  *resfd  = -1;
  *status = nullptr;
  return false;
HardError:
  Debug("udpnet", "creating a udp socket port = %d---hard failure", ats_ip_port_host_order(local_addr));
  if (fd != -1) {
    SocketManager::close(fd);
  }
  *resfd  = -1;
  *status = ACTION_IO_ERROR;
  return false;
}

Action *
UDPNetProcessor::UDPBind(Continuation *cont, sockaddr const *addr, int fd, int send_bufsize, int recv_bufsize)
{
  int res              = 0;
  UnixUDPConnection *n = nullptr;
  IpEndpoint myaddr;
  int myaddr_len     = sizeof(myaddr);
  PollCont *pc       = nullptr;
  PollDescriptor *pd = nullptr;
  bool need_bind     = true;

  if (fd == -1) {
    if ((res = SocketManager::socket(addr->sa_family, SOCK_DGRAM, 0)) < 0) {
      goto Lerror;
    }
    fd = res;
  } else {
    need_bind = false;
  }
  if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
    goto Lerror;
  }

  if (addr->sa_family == AF_INET) {
    bool succeeded = false;
    int enable     = 1;
#ifdef IP_PKTINFO
    if (safe_setsockopt(fd, IPPROTO_IP, IP_PKTINFO, reinterpret_cast<char *>(&enable), sizeof(enable)) == 0) {
      succeeded = true;
    }
#endif
#ifdef IP_RECVDSTADDR
    if (safe_setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, reinterpret_cast<char *>(&enable), sizeof(enable)) == 0) {
      succeeded = true;
    }
#endif
    if (!succeeded) {
      Debug("udpnet", "setsockeopt for pktinfo failed");
      goto Lerror;
    }
  } else if (addr->sa_family == AF_INET6) {
    bool succeeded = false;
    int enable     = 1;
#ifdef IPV6_PKTINFO
    if (safe_setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, reinterpret_cast<char *>(&enable), sizeof(enable)) == 0) {
      succeeded = true;
    }
#endif
#ifdef IPV6_RECVPKTINFO
    if (safe_setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, reinterpret_cast<char *>(&enable), sizeof(enable)) == 0) {
      succeeded = true;
    }
#endif
    if (!succeeded) {
      Debug("udpnet", "setsockeopt for pktinfo failed");
      goto Lerror;
    }
  }

  // If this is a class D address (i.e. multicast address), use REUSEADDR.
  if (ats_is_ip_multicast(addr)) {
    int enable_reuseaddr = 1;

    if (safe_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&enable_reuseaddr), sizeof(enable_reuseaddr)) < 0) {
      goto Lerror;
    }
  }

  if (need_bind && ats_is_ip6(addr) && safe_setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, SOCKOPT_ON, sizeof(int)) < 0) {
    goto Lerror;
  }

  if (safe_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, SOCKOPT_ON, sizeof(int)) < 0) {
    Debug("udpnet", "setsockopt for SO_REUSEPORT failed");
    goto Lerror;
  }

#ifdef SO_REUSEPORT_LB
  if (safe_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT_LB, SOCKOPT_ON, sizeof(int)) < 0) {
    Debug("udpnet", "setsockopt for SO_REUSEPORT_LB failed");
    goto Lerror;
  }
#endif

  if (need_bind && (SocketManager::ink_bind(fd, addr, ats_ip_size(addr)) < 0)) {
    Debug("udpnet", "ink_bind failed");
    goto Lerror;
  }

  if (recv_bufsize) {
    if (unlikely(SocketManager::set_rcvbuf_size(fd, recv_bufsize))) {
      Debug("udpnet", "set_dnsbuf_size(%d) failed", recv_bufsize);
    }
  }
  if (send_bufsize) {
    if (unlikely(SocketManager::set_sndbuf_size(fd, send_bufsize))) {
      Debug("udpnet", "set_dnsbuf_size(%d) failed", send_bufsize);
    }
  }
  if (safe_getsockname(fd, &myaddr.sa, &myaddr_len) < 0) {
    goto Lerror;
  }
  n = new UnixUDPConnection(fd);

  Debug("udpnet", "UDPNetProcessor::UDPBind: %p fd=%d", n, fd);
  n->setBinding(&myaddr.sa);
  n->bindToThread(cont, cont->getThreadAffinity());

  pc = get_UDPPollCont(n->ethread);
  pd = pc->pollDescriptor;

  n->ep.start(pd, n, get_UDPNetHandler(cont->getThreadAffinity()), EVENTIO_READ);

  cont->handleEvent(NET_EVENT_DATAGRAM_OPEN, n);
  return ACTION_RESULT_DONE;
Lerror:
  if (fd != NO_FD) {
    SocketManager::close(fd);
  }
  Debug("udpnet", "Error: %s (%d)", strerror(errno), errno);

  cont->handleEvent(NET_EVENT_DATAGRAM_ERROR, nullptr);
  return ACTION_IO_ERROR;
}

// send out all packets that need to be sent out as of time=now
#ifdef SOL_UDP
UDPQueue::UDPQueue(bool enable_gso) : use_udp_gso(enable_gso) {}
#else
UDPQueue::UDPQueue(bool enable_gso)
{
  if (enable_gso) {
    Warning("Attempted to use UDP GSO per configuration, but it is unavailable");
  }
}
#endif

UDPQueue::~UDPQueue() {}

/*
 * Driver function that aggregates packets across cont's and sends them
 */
void
UDPQueue::service(UDPNetHandler *nh)
{
  (void)nh;
  ink_hrtime now     = Thread::get_hrtime_updated();
  uint64_t timeSpent = 0;
  uint64_t pktSendStartTime;
  ink_hrtime pktSendTime;
  UDPPacketInternal *p = nullptr;

  SList(UDPPacketInternal, alink) aq(outQueue.popall());
  Queue<UDPPacketInternal> stk;
  while ((p = aq.pop())) {
    stk.push(p);
  }

  // walk backwards down list since this is actually an atomic stack.
  while ((p = stk.pop())) {
    ink_assert(p->link.prev == nullptr);
    ink_assert(p->link.next == nullptr);
    // insert into our queue.
    Debug("udp-send", "Adding %p", p);
    if (p->conn->lastPktStartTime == 0) {
      pktSendStartTime = std::max(now, p->delivery_time);
    } else {
      pktSendTime      = p->delivery_time;
      pktSendStartTime = std::max(std::max(now, pktSendTime), p->delivery_time);
    }
    p->conn->lastPktStartTime = pktSendStartTime;
    p->delivery_time          = pktSendStartTime;

    pipeInfo.addPacket(p, now);
  }

  pipeInfo.advanceNow(now);
  SendPackets();

  timeSpent = ink_hrtime_to_msec(now - last_report);
  if (timeSpent > 10000) {
    last_report = now;
    added       = 0;
    packets     = 0;
  }
  last_service = now;
}

void
UDPQueue::SendPackets()
{
  UDPPacketInternal *p;
  static ink_hrtime lastCleanupTime = Thread::get_hrtime_updated();
  ink_hrtime now                    = Thread::get_hrtime_updated();
  ink_hrtime send_threshold_time    = now + SLOT_TIME;
  int32_t bytesThisSlot = INT_MAX, bytesUsed = 0;
  int32_t bytesThisPipe;
  int64_t pktLen;

  bytesThisSlot = INT_MAX;

#ifdef UIO_MAXIOV
  constexpr int N_MAX_PACKETS = UIO_MAXIOV; // The limit comes from sendmmsg
#else
  constexpr int N_MAX_PACKETS = 1024;
#endif
  UDPPacketInternal *packets[N_MAX_PACKETS];
  int nsent;
  int npackets;

sendPackets:
  nsent         = 0;
  npackets      = 0;
  bytesThisPipe = bytesThisSlot;

  while ((bytesThisPipe > 0) && (pipeInfo.firstPacket(send_threshold_time))) {
    p      = pipeInfo.getFirstPacket();
    pktLen = p->getPktLength();

    if (p->conn->shouldDestroy()) {
      goto next_pkt;
    }
    if (p->conn->GetSendGenerationNumber() != p->reqGenerationNum) {
      goto next_pkt;
    }

    bytesUsed           += pktLen;
    bytesThisPipe       -= pktLen;
    packets[npackets++] = p;
  next_pkt:
    if (bytesThisPipe < 0 || npackets == N_MAX_PACKETS) {
      break;
    }
  }

  if (npackets > 0) {
    nsent = SendMultipleUDPPackets(packets, npackets);
  }
  for (int i = 0; i < nsent; ++i) {
    packets[i]->free();
  }

  bytesThisSlot -= bytesUsed;

  if ((bytesThisSlot > 0) && nsent) {
    // redistribute the slack...
    now = Thread::get_hrtime_updated();
    if (pipeInfo.firstPacket(now) == nullptr) {
      pipeInfo.advanceNow(now);
    }
    goto sendPackets;
  }

  if ((g_udp_periodicFreeCancelledPkts) && (now - lastCleanupTime > ink_hrtime_from_sec(g_udp_periodicFreeCancelledPkts))) {
    pipeInfo.FreeCancelledPackets(g_udp_periodicCleanupSlots);
    lastCleanupTime = now;
  }
}

void
UDPQueue::SendUDPPacket(UDPPacketInternal *p)
{
  struct msghdr msg;
  struct iovec iov[32];
  int n, count = 0;

  p->conn->lastSentPktStartTime = p->delivery_time;
  Debug("udp-send", "Sending %p", p);

  msg.msg_control    = nullptr;
  msg.msg_controllen = 0;
  msg.msg_flags      = 0;
  msg.msg_name       = reinterpret_cast<caddr_t>(&p->to.sa);
  msg.msg_namelen    = ats_ip_size(p->to);

  if (p->segment_size > 0) {
    ink_assert(p->chain->next == nullptr);
    msg.msg_iov    = iov;
    msg.msg_iovlen = 1;
#ifdef SOL_UDP
    if (use_udp_gso) {
      iov[0].iov_base = p->chain.get()->start();
      iov[0].iov_len  = p->chain.get()->size();

      union udp_segment_hdr {
        char buf[CMSG_SPACE(sizeof(uint16_t))];
        struct cmsghdr align;
      } u;
      msg.msg_control    = u.buf;
      msg.msg_controllen = sizeof(u.buf);

      struct cmsghdr *cm           = CMSG_FIRSTHDR(&msg);
      cm->cmsg_level               = SOL_UDP;
      cm->cmsg_type                = UDP_SEGMENT;
      cm->cmsg_len                 = CMSG_LEN(sizeof(uint16_t));
      *((uint16_t *)CMSG_DATA(cm)) = p->segment_size;

      count = 0;
      while (true) {
        // stupid Linux problem: sendmsg can return EAGAIN
        n = ::sendmsg(p->conn->getFd(), &msg, 0);
        if (n >= 0) {
          break;
        }
        if (errno == EIO && use_udp_gso) {
          Warning("Disabling UDP GSO due to an error");
          use_udp_gso = false;
          SendUDPPacket(p);
          return;
        }
        if (errno == EAGAIN) {
          ++count;
          if ((g_udp_numSendRetries > 0) && (count >= g_udp_numSendRetries)) {
            // tried too many times; give up
            Debug("udpnet", "Send failed: too many retries");
            return;
          }
        } else {
          Debug("udp-send", "Error: %s (%d)", strerror(errno), errno);
          return;
        }
      }
    } else {
#endif
      // Send segments seprately if UDP_SEGMENT is not supported
      int offset = 0;
      while (offset < p->chain.get()->size()) {
        iov[0].iov_base = p->chain.get()->start() + offset;
        iov[0].iov_len = std::min(static_cast<long>(p->segment_size), p->chain.get()->end() - static_cast<char *>(iov[0].iov_base));

        count = 0;
        while (true) {
          // stupid Linux problem: sendmsg can return EAGAIN
          n = ::sendmsg(p->conn->getFd(), &msg, 0);
          if (n >= 0) {
            break;
          }
          if (errno == EAGAIN) {
            ++count;
            if ((g_udp_numSendRetries > 0) && (count >= g_udp_numSendRetries)) {
              // tried too many times; give up
              Debug("udpnet", "Send failed: too many retries");
              return;
            }
          } else {
            Debug("udp-send", "Error: %s (%d)", strerror(errno), errno);
            return;
          }
        }

        offset += iov[0].iov_len;
      }
      ink_assert(offset == p->chain.get()->size());
#ifdef SOL_UDP
    } // use_udp_segment
#endif
  } else {
    // Nothing is special
    int iov_len = 0;
    for (IOBufferBlock *b = p->chain.get(); b != nullptr; b = b->next.get()) {
      iov[iov_len].iov_base = static_cast<caddr_t>(b->start());
      iov[iov_len].iov_len  = b->size();
      iov_len++;
    }
    msg.msg_iov    = iov;
    msg.msg_iovlen = iov_len;

    count = 0;
    while (true) {
      // stupid Linux problem: sendmsg can return EAGAIN
      n = ::sendmsg(p->conn->getFd(), &msg, 0);
      if ((n >= 0) || (errno != EAGAIN)) {
        // send succeeded or some random error happened.
        if (n < 0) {
          Debug("udp-send", "Error: %s (%d)", strerror(errno), errno);
        }

        break;
      }
      if (errno == EAGAIN) {
        ++count;
        if ((g_udp_numSendRetries > 0) && (count >= g_udp_numSendRetries)) {
          // tried too many times; give up
          Debug("udpnet", "Send failed: too many retries");
          break;
        }
      }
    }
  }
}

void
UDPQueue::send(UDPPacket *p)
{
  // XXX: maybe fastpath for immediate send?
  outQueue.push((UDPPacketInternal *)p);
}

int
UDPQueue::SendMultipleUDPPackets(UDPPacketInternal **p, uint16_t n)
{
#ifdef HAVE_SENDMMSG
  struct mmsghdr *msgvec;
  int msgvec_size;

#ifdef SOL_UDP
  union udp_segment_hdr {
    char buf[CMSG_SPACE(sizeof(uint16_t))];
    struct cmsghdr align;
  };
  if (use_udp_gso) {
    msgvec_size = sizeof(struct mmsghdr) * n;
  } else {
    msgvec_size = sizeof(struct mmsghdr) * n * 64;
  }
#else
  msgvec_size = sizeof(struct mmsghdr) * n * 64;
#endif
  // The sizeof(struct msghdr) is 56 bytes or so. It can be too big to stack (alloca).
  IOBufferBlock *tmp = new_IOBufferBlock();
  tmp->alloc(iobuffer_size_to_index(msgvec_size, BUFFER_SIZE_INDEX_1M));
  msgvec = reinterpret_cast<struct mmsghdr *>(tmp->buf());
  memset(msgvec, 0, msgvec_size);

  // The sizeof(struct iove) is 16 bytes or so. It can be too big to stack (alloca).
  int iovec_size      = sizeof(struct iovec) * n * 64;
  IOBufferBlock *tmp2 = new_IOBufferBlock();
  tmp2->alloc(iobuffer_size_to_index(iovec_size, BUFFER_SIZE_INDEX_1M));
  struct iovec *iovec = reinterpret_cast<struct iovec *>(tmp2->buf());
  memset(iovec, 0, iovec_size);
  int iovec_used = 0;

  int vlen = 0;
  int fd   = p[0]->conn->getFd();
  for (int i = 0; i < n; ++i) {
    UDPPacketInternal *packet;
    struct msghdr *msg;
    struct iovec *iov;
    int iov_len;

    packet                             = p[i];
    packet->conn->lastSentPktStartTime = packet->delivery_time;
    ink_assert(packet->conn->getFd() == fd);
    if (packet->segment_size > 0) {
      // Presumes one big super buffer is given
      ink_assert(packet->chain->next == nullptr);
#ifdef SOL_UDP
      if (use_udp_gso) {
        msg              = &msgvec[vlen].msg_hdr;
        msg->msg_name    = reinterpret_cast<caddr_t>(&packet->to.sa);
        msg->msg_namelen = ats_ip_size(packet->to);

        union udp_segment_hdr *u;
        u                   = static_cast<union udp_segment_hdr *>(alloca(sizeof(union udp_segment_hdr)));
        msg->msg_control    = u->buf;
        msg->msg_controllen = sizeof(u->buf);
        iov                 = &iovec[iovec_used++];
        iov_len             = 1;
        iov->iov_base       = packet->chain.get()->start();
        iov->iov_len        = packet->chain.get()->size();
        msg->msg_iov        = iov;
        msg->msg_iovlen     = iov_len;

        struct cmsghdr *cm           = CMSG_FIRSTHDR(msg);
        cm->cmsg_level               = SOL_UDP;
        cm->cmsg_type                = UDP_SEGMENT;
        cm->cmsg_len                 = CMSG_LEN(sizeof(uint16_t));
        *((uint16_t *)CMSG_DATA(cm)) = packet->segment_size;
        vlen++;
      } else {
#endif
        // UDP_SEGMENT is unavailable
        // Send the given data as multiple messages
        int offset = 0;
        while (offset < packet->chain.get()->size()) {
          msg              = &msgvec[vlen].msg_hdr;
          msg->msg_name    = reinterpret_cast<caddr_t>(&packet->to.sa);
          msg->msg_namelen = ats_ip_size(packet->to);
          iov              = &iovec[iovec_used++];
          iov_len          = 1;
          iov->iov_base    = packet->chain.get()->start() + offset;
          iov->iov_len =
            std::min(packet->segment_size, static_cast<uint16_t>(packet->chain.get()->end() - static_cast<char *>(iov->iov_base)));
          msg->msg_iov    = iov;
          msg->msg_iovlen = iov_len;
          offset          += iov->iov_len;
          vlen++;
        }
        ink_assert(offset == packet->chain.get()->size());
#ifdef SOL_UDP
      } // use_udp_gso
#endif
    } else {
      // Nothing is special
      msg              = &msgvec[vlen].msg_hdr;
      msg->msg_name    = reinterpret_cast<caddr_t>(&packet->to.sa);
      msg->msg_namelen = ats_ip_size(packet->to);
      iov              = &iovec[iovec_used++];
      iov_len          = 0;
      for (IOBufferBlock *b = packet->chain.get(); b != nullptr; b = b->next.get()) {
        iov[iov_len].iov_base = static_cast<caddr_t>(b->start());
        iov[iov_len].iov_len  = b->size();
        iov_len++;
      }
      msg->msg_iov    = iov;
      msg->msg_iovlen = iov_len;
      vlen++;
    }
  }

  if (vlen == 0) {
    return 0;
  }

  int res = ::sendmmsg(fd, msgvec, vlen, 0);
  if (res < 0) {
#ifdef SOL_UDP
    if (use_udp_gso && errno == EIO) {
      Warning("Disabling UDP GSO due to an error");
      Debug("udp-send", "Disabling UDP GSO due to an error");
      use_udp_gso = false;
      return SendMultipleUDPPackets(p, n);
    } else {
      Debug("udp-send", "udp_gso=%d res=%d errno=%d", use_udp_gso, res, errno);
      return res;
    }
#else
    Debug("udp-send", "res=%d errno=%d", res, errno);
    return res;
#endif
  }

  if (res > 0) {
#ifdef SOL_UDP
    if (use_udp_gso) {
      Debug("udp-send", "Sent %d messages by processing %d UDPPackets (GSO)", res, n);
    } else {
#endif
      int i    = 0;
      int nmsg = res;
      for (i = 0; i < n && res > 0; ++i) {
        if (p[i]->segment_size == 0) {
          res -= 1;
        } else {
          res -= (p[i]->chain.get()->size() / p[i]->segment_size) + ((p[i]->chain.get()->size() % p[i]->segment_size) != 0);
        }
      }
      Debug("udp-send", "Sent %d messages by processing %d UDPPackets", nmsg, i);
      res = i;
#ifdef SOL_UDP
    }
#endif
  }
  tmp->free();
  tmp2->free();

  return res;
#else
  // sendmmsg is unavailable
  for (int i = 0; i < n; ++i) {
    SendUDPPacket(p[i]);
  }
  return n;
#endif
}

#undef LINK

UDPNetHandler::UDPNetHandler(bool enable_gso) : udpOutQueue(enable_gso)
{
  nextCheck = Thread::get_hrtime_updated() + HRTIME_MSECONDS(1000);
  lastCheck = 0;
  SET_HANDLER(&UDPNetHandler::startNetEvent);
}

int
UDPNetHandler::startNetEvent(int event, Event *e)
{
  (void)event;
  SET_HANDLER(&UDPNetHandler::mainNetEvent);
  trigger_event = e;
  e->schedule_every(-HRTIME_MSECONDS(UDP_NH_PERIOD));
  return EVENT_CONT;
}

int
UDPNetHandler::mainNetEvent(int event, Event *e)
{
  ink_assert(trigger_event == e && event == EVENT_POLL);
  return this->waitForActivity(net_config_poll_timeout);
}

int
UDPNetHandler::waitForActivity(ink_hrtime timeout)
{
  UnixUDPConnection *uc;
  PollCont *pc = get_UDPPollCont(this->thread);
  pc->do_poll(timeout);

  /* Notice: the race between traversal of newconn_list and UDPBind()
   *
   * If the UDPBind() is called after the traversal of newconn_list,
   * the UDPConnection, the one from the pollDescriptor->result, did not push into the open_list.
   *
   * TODO:
   *
   * Take UnixNetVConnection::acceptEvent() as reference to create UnixUDPConnection::newconnEvent().
   */

  // handle new UDP connection
  SList(UnixUDPConnection, newconn_alink) ncq(newconn_list.popall());
  while ((uc = ncq.pop())) {
    if (uc->shouldDestroy()) {
      open_list.remove(uc); // due to the above race
      uc->Release();
    } else {
      ink_assert(uc->mutex && uc->continuation);
      open_list.in_or_enqueue(uc); // due to the above race
    }
  }

  // handle UDP outgoing engine
  udpOutQueue.service(this);

  // handle UDP read operations
  int i        = 0;
  EventIO *epd = nullptr;
  for (i = 0; i < pc->pollDescriptor->result; i++) {
    epd       = static_cast<EventIO *> get_ev_data(pc->pollDescriptor, i);
    int flags = get_ev_events(pc->pollDescriptor, i);
    epd->process_event(flags);
  } // end for

  // remove dead UDP connections
  ink_hrtime now = Thread::get_hrtime_updated();
  if (now >= nextCheck) {
    forl_LL(UnixUDPConnection, xuc, open_list)
    {
      ink_assert(xuc->mutex && xuc->continuation);
      ink_assert(xuc->refcount >= 1);
      if (xuc->shouldDestroy()) {
        open_list.remove(xuc);
        xuc->Release();
      }
    }
    nextCheck = Thread::get_hrtime_updated() + HRTIME_MSECONDS(1000);
  }
  // service UDPConnections with data ready for callback.
  Que(UnixUDPConnection, callback_link) q = udp_callbacks;
  udp_callbacks.clear();
  while ((uc = q.dequeue())) {
    ink_assert(uc->mutex && uc->continuation);
    if (udpNetInternal.udp_callback(this, uc, this->thread)) { // not successful
      // schedule on a thread of its own.
      ink_assert(uc->callback_link.next == nullptr);
      ink_assert(uc->callback_link.prev == nullptr);
      udp_callbacks.enqueue(uc);
    } else {
      ink_assert(uc->callback_link.next == nullptr);
      ink_assert(uc->callback_link.prev == nullptr);
      uc->onCallbackQueue = 0;
      uc->Release();
    }
  }

  return EVENT_CONT;
}

void
UDPNetHandler::signalActivity()
{
#if HAVE_EVENTFD
  uint64_t counter = 1;
  ATS_UNUSED_RETURN(write(thread->evfd, &counter, sizeof(uint64_t)));
#elif TS_USE_PORT
  PollDescriptor *pd = get_PollDescriptor(thread);
  ATS_UNUSED_RETURN(port_send(pd->port_fd, 0, thread->ep));
#else
  char dummy = 1;
  ATS_UNUSED_RETURN(write(thread->evpipe[1], &dummy, 1));
#endif
}
