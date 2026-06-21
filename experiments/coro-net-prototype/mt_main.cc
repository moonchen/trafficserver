/** @file
 *  Multi-threaded demonstration of the EThread-affinity model (Seam 2).
 *
 *  Threads:
 *    - N worker reactors, each its own thread + its own backend (per-thread ring
 *      / epoll set). A connection is confined to one worker for its lifetime.
 *    - 1 acceptor reactor (own thread). It accepts and HANDS each fd to a worker
 *      via post_remote — the one synchronized cross-thread channel.
 *    - 1 client reactor (own thread) driving the test clients.
 *
 *  What it shows:
 *    1. Accept hand-off across threads (acceptor -> worker) by message-passing.
 *    2. Connection MIGRATION across worker threads mid-session: after its first
 *       transaction, one VC is moved from worker 1 to worker 2 (modelling an
 *       idle origin connection migrating onto the client's thread). The coroutine
 *       suspends on the source thread and resumes on the destination thread —
 *       no lock, just a hand-off.
 *    3. There is NO per-VC mutex anywhere. Confinement + post_remote is the only
 *       synchronization. Run under ThreadSanitizer to confirm.
 *
 *      ./coro_net_mt epoll
 *      ./coro_net_mt uring
 */
#include "async_socket.h"
#include "coro_netvc.h"
#include "epoll_backend.h"
#include "reactor.h"
#include "uring_backend.h"

#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace coronet;

namespace
{

constexpr int N_WORKERS = 3;
constexpr int N_CONNS   = 4;
constexpr int N_TXN     = 2; // transactions (round-trips) per connection

struct Stats {
  std::atomic<int> clients_done{0};
  std::atomic<int> server_done{0};
};

std::unique_ptr<IBackend>
make_backend(const std::string &which, int id)
{
  if (which == "uring") {
#ifdef HAVE_LIBURING
    return std::make_unique<UringBackend>();
#endif
  }
  (void)id;
  return std::make_unique<EpollBackend>();
}

int
make_listener(uint16_t &out_port)
{
  int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  int on = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
  sockaddr_in a{};
  a.sin_family      = AF_INET;
  a.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
  if (::bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof a) < 0) {
    ::perror("bind");
    ::exit(1);
  }
  ::listen(fd, 64);
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

// ---- server side: one echo transaction, then a callback --------------------

using Buf = std::array<char, 256>;

void
do_one_txn(CoroNetVConnection *vc, Buf *buf, std::function<void()> on_done)
{
  vc->do_io_read(buf->data(), buf->size(), [vc, buf, on_done = std::move(on_done)](int ev) mutable {
    if (ev != VC_READ_READY && ev != VC_READ_COMPLETE) {
      vc->do_io_close();
      return;
    }
    size_t n = vc->read_done();
    vc->do_io_write(buf->data(), n, [on_done = std::move(on_done)](int ev2) {
      if (ev2 == VC_WRITE_COMPLETE) {
        on_done();
      }
    });
  });
}

// A two-transaction echo session. If `migrate_dest` is non-null, the connection
// migrates to that worker between the two transactions.
void
start_session(CoroNetVConnection *vc, Reactor *migrate_dest)
{
  auto *buf = new Buf;
  do_one_txn(vc, buf, [vc, buf, migrate_dest] {
    auto finish = [vc, buf] {
      do_one_txn(vc, buf, [vc, buf] {
        delete buf;
        vc->do_io_close();
      });
    };
    if (migrate_dest) {
      vc->request_migrate(*migrate_dest, finish); // finish() runs on the new thread
    } else {
      finish();
    }
  });
}

// ---- coroutines -------------------------------------------------------------

DetachedTask
accept_loop(Reactor &acc, int lfd, std::vector<Reactor *> *workers, Stats *st)
{
  AsyncSocket listener(acc, lfd);
  for (int i = 0; i < N_CONNS; ++i) {
    sockaddr_storage ss{};
    socklen_t        sl  = sizeof ss;
    int              cfd = co_await listener.accept(reinterpret_cast<sockaddr *>(&ss), &sl);
    if (cfd < 0) {
      ::printf("  accept failed: %d\n", cfd);
      break;
    }
    Reactor *w        = (*workers)[i % N_WORKERS];
    bool     migrate  = (i == 0); // the first connection will migrate worker1 -> worker2
    Reactor *dest     = (*workers)[1 % N_WORKERS];
    ::printf("  acceptor(reactor %d): handed conn %d to worker reactor %d%s\n", acc.id(), i, w->id(),
             migrate ? " (will migrate)" : "");
    // Create and drive the VC ON the worker thread.
    w->post_remote([w, cfd, i, migrate, dest, st] {
      auto *vc = new CoroNetVConnection(*w, cfd, i, [st] { st->server_done.fetch_add(1); });
      start_session(vc, migrate ? dest : nullptr);
    });
  }
}

DetachedTask
client(Reactor &r, uint16_t port, int idx, Stats *st)
{
  AsyncSocket s(r, make_client_fd());
  auto        addr = loopback(port);
  int         cr   = co_await s.connect(reinterpret_cast<sockaddr *>(&addr), sizeof addr);
  assert(cr == 0);

  bool ok = true;
  for (int t = 0; t < N_TXN; ++t) {
    char m[64];
    int  len = ::snprintf(m, sizeof m, "req-%d-txn-%d", idx, t);
    co_await s.send(m, len);
    char buf[64];
    int  n = co_await s.recv(buf, sizeof buf);
    ok     = ok && n == len && std::memcmp(buf, m, len) == 0;
  }
  co_await s.close();
  ::printf("  client %d: %d round-trips, match=%s\n", idx, N_TXN, ok ? "YES" : "NO");
  assert(ok);
  st->clients_done.fetch_add(1);
}

} // namespace

int
main(int argc, char **argv)
{
  std::string which = argc > 1 ? argv[1] : "epoll";

  Stats                  st;
  std::vector<Reactor *> workers(N_WORKERS, nullptr);
  std::atomic<Reactor *> acceptorR{nullptr};
  std::atomic<Reactor *> clientR{nullptr};
  std::atomic<int>       ready{0};

  // Worker threads: each constructs its own backend + reactor ON its thread.
  std::vector<std::thread> worker_threads;
  for (int i = 0; i < N_WORKERS; ++i) {
    worker_threads.emplace_back([&, i] {
      auto    be = make_backend(which, i + 1);
      Reactor r(*be, i + 1);
      workers[i] = &r;
      ready.fetch_add(1);
      r.run();
    });
  }
  while (ready.load() < N_WORKERS) {
    std::this_thread::yield();
  }

  uint16_t port = 0;
  int      lfd  = make_listener(port);
  ::printf("== coro-net MT prototype, backend = %s, %d workers, listening on 127.0.0.1:%u ==\n", which.c_str(), N_WORKERS,
           port);

  // Acceptor thread.
  std::thread acceptor_thread([&] {
    auto    be = make_backend(which, 0);
    Reactor r(*be, 0);
    acceptorR.store(&r);
    accept_loop(r, lfd, &workers, &st);
    r.run();
  });

  // Client thread.
  std::thread client_thread([&] {
    auto    be = make_backend(which, 99);
    Reactor r(*be, 99);
    clientR.store(&r);
    for (int i = 0; i < N_CONNS; ++i) {
      client(r, port, i, &st);
    }
    r.run();
  });

  while (acceptorR.load() == nullptr || clientR.load() == nullptr) {
    std::this_thread::yield();
  }

  // Wait for completion.
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
  while ((st.clients_done.load() < N_CONNS || st.server_done.load() < N_CONNS) &&
         std::chrono::steady_clock::now() < deadline) {
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }

  // Ordered shutdown: stop the PRODUCERS first (acceptor + clients) and join
  // them, so nobody can post_remote to a worker any more. Only then stop the
  // workers. This removes the one cross-thread interaction that would otherwise
  // race a worker's teardown.
  acceptorR.load()->stop();
  clientR.load()->stop();
  acceptor_thread.join();
  client_thread.join();

  for (Reactor *w : workers) {
    w->stop();
  }
  for (auto &t : worker_threads) {
    t.join();
  }
  ::close(lfd);

  int c = st.clients_done.load(), s = st.server_done.load();
  ::printf("== done: clients %d/%d, server VCs freed %d/%d ==\n", c, N_CONNS, s, N_CONNS);
  return (c == N_CONNS && s == N_CONNS) ? 0 : 1;
}
