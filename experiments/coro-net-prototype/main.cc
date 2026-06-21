/** @file
 *  Runnable demonstration of the three seams.
 *
 *  Topology (all in one process, one thread, one Reactor):
 *
 *      clientA ──connect/send/recv──►  server VC 0  (CoroNetVConnection echo)
 *        (raw AsyncSocket awaitables)     (do_io_read/do_io_write facade)
 *
 *      clientB ──connect, then idle──►  server VC 1  (CoroNetVConnection)
 *                                          do_io_read posted, then do_io_close
 *                                          while the recv is in flight  ← the
 *                                          cancel-then-unwind lifetime showcase
 *
 *  Run it twice, once per engine, to prove the layers above Seam 1 are identical:
 *      ./coro_net epoll
 *      ./coro_net uring
 */
#include "async_socket.h"
#include "coro_netvc.h"
#include "epoll_backend.h"
#include "reactor.h"
#include "uring_backend.h"

#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using namespace coronet;

namespace
{

struct Demo {
  Reactor *r;
  int      done = 0;
  int      need = 3;
  void
  one(const char *what)
  {
    ++done;
    ::printf("  ✓ %s (%d/%d)\n", what, done, need);
    if (done >= need) {
      r->stop();
    }
  }
};

int
make_listener(uint16_t &out_port)
{
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  int on = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
  sockaddr_in a{};
  a.sin_family      = AF_INET;
  a.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
  a.sin_port        = 0;
  if (::bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof a) < 0) {
    ::perror("bind");
    ::exit(1);
  }
  ::listen(fd, 16);
  socklen_t l = sizeof a;
  ::getsockname(fd, reinterpret_cast<sockaddr *>(&a), &l);
  out_port = ::ntohs(a.sin_port);
  return fd;
}

int
make_client_fd()
{
  return ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
}

sockaddr_in
loopback(uint16_t port)
{
  sockaddr_in a{};
  a.sin_family      = AF_INET;
  a.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
  a.sin_port        = ::htons(port);
  return a;
}

// ---- server side: echo using the NetVConnection facade (Seam 3) -------------

void
start_echo_session(CoroNetVConnection *vc)
{
  auto *buf = new std::array<char, 128>;
  vc->do_io_read(buf->data(), buf->size(), [vc, buf](int ev) {
    if (ev == VC_READ_READY || ev == VC_READ_COMPLETE) {
      size_t n = vc->read_done();
      ::printf("    [VC %d] read %zu bytes; echoing\n", vc->id(), n);
      vc->do_io_write(buf->data(), n, [vc, buf](int ev2) {
        if (ev2 == VC_WRITE_COMPLETE) {
          ::printf("    [VC %d] echo written; closing\n", vc->id());
          vc->do_io_close();
        }
        delete buf;
      });
    } else {
      delete buf;
      vc->do_io_close();
    }
  });
}

// ---- the coroutines ---------------------------------------------------------

DetachedTask
accept_loop(Reactor &r, int lfd, Demo &demo)
{
  AsyncSocket listener(r, lfd);
  for (int i = 0; i < 2; ++i) {
    sockaddr_storage ss{};
    socklen_t        sl  = sizeof ss;
    int              cfd = co_await listener.accept(reinterpret_cast<sockaddr *>(&ss), &sl);
    if (cfd < 0) {
      ::printf("  accept failed: %d\n", cfd);
      break;
    }
    if (i == 0) {
      auto *vc = new CoroNetVConnection(r, cfd, 0, [&demo] { demo.one("echo VC freed cleanly"); });
      start_echo_session(vc);
    } else {
      // Cancellation showcase: start a read that will never get data (clientB
      // never sends), then close it while that recv is in flight. The read is
      // cancelled before its continuation runs, so the buffer is reclaimed in the
      // VC's on_freed hook rather than the read continuation.
      auto *buf = new std::array<char, 64>;
      auto *vc  = new CoroNetVConnection(r, cfd, 1, [&demo, buf] {
        delete buf;
        demo.one("cancelled-on-close VC freed (no UAF)");
      });
      vc->do_io_read(buf->data(), buf->size(), [](int) {});
      r.post([vc] { vc->do_io_close(); }); // runs after the recv is submitted
    }
  }
}

DetachedTask
client_echo(Reactor &r, uint16_t port, Demo &demo)
{
  AsyncSocket s(r, make_client_fd());
  auto        addr = loopback(port);
  int         cr   = co_await s.connect(reinterpret_cast<sockaddr *>(&addr), sizeof addr);
  assert(cr == 0);

  static const char msg[] = "hello, coroutine net!";
  co_await s.send(msg, sizeof msg - 1);

  char buf[128];
  int  n  = co_await s.recv(buf, sizeof buf);
  bool ok = n == static_cast<int>(sizeof msg - 1) && std::memcmp(buf, msg, n) == 0;
  ::printf("  clientA: sent %zu bytes, got %d back, match=%s\n", sizeof msg - 1, n, ok ? "YES" : "NO");
  assert(ok);
  co_await s.close();
  demo.one("clientA round-trip verified");
}

// Kept alive (not leaked) for the duration of the program so the idle
// connection stays open — its server-side recv is what the cancel-on-close path
// cancels. Reachable at exit, so LeakSanitizer is happy.
std::vector<std::unique_ptr<AsyncSocket>> g_keepalive;

DetachedTask
client_idle(Reactor &r, uint16_t port)
{
  AsyncSocket *s    = g_keepalive.emplace_back(std::make_unique<AsyncSocket>(r, make_client_fd())).get();
  auto         addr = loopback(port);
  co_await s->connect(reinterpret_cast<sockaddr *>(&addr), sizeof addr);
  ::printf("  clientB: connected and idling (never sends)\n");
}

} // namespace

int
main(int argc, char **argv)
{
  std::string which = argc > 1 ? argv[1] : "epoll";

  std::unique_ptr<IBackend> backend;
  if (which == "uring") {
#ifdef HAVE_LIBURING
    backend = std::make_unique<UringBackend>();
#else
    ::printf("built without liburing; falling back to epoll\n");
    backend = std::make_unique<EpollBackend>();
#endif
  } else {
    backend = std::make_unique<EpollBackend>();
  }

  ::printf("== coro-net prototype, backend = %s ==\n", backend->name());

  Reactor reactor(*backend);
  Demo    demo{&reactor};

  uint16_t port = 0;
  int      lfd  = make_listener(port);

  accept_loop(reactor, lfd, demo);
  client_echo(reactor, port, demo);
  client_idle(reactor, port);

  reactor.run();

  ::printf("== done (%d/%d checks passed) ==\n", demo.done, demo.need);
  return demo.done == demo.need ? 0 : 1;
}
