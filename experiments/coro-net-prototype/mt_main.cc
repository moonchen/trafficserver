/** @file
 *  Multi-threaded demonstration of the EThread-affinity model (Seam 2).
 *
 *  Threads:
 *    - N worker reactors, each its own thread + its own backend (per-thread ring
 *      / epoll set). A connection is confined to one worker for its lifetime.
 *    - 1 acceptor reactor (own thread). It accepts and HANDS each fd to a worker
 *      via post_remote — one synchronized cross-thread channel.
 *    - 1 client reactor (own thread) driving the test clients.
 *
 *  What it shows:
 *    1. Accept hand-off across threads (acceptor -> worker) by message-passing.
 *    2. SYNCHRONOUS, DESTINATION-PULLED migration (cf. ATS migrateToCurrentThread).
 *       After its first transaction, connection 0 is released into a shared
 *       session pool, BARE (no armed io_uring op). A *different* worker later
 *       pulls it from the pool and calls migrate_here() on its own reactor — a
 *       synchronous adopt, no callback, no cross-thread message — then drives the
 *       second transaction. The pool's mutex is the only synchronization, exactly
 *       as ATS relies on the session-pool lock.
 *    3. There is NO per-VC mutex anywhere. Run under ThreadSanitizer to confirm.
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
#include <functional>
#include <memory>
#include <mutex>
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

// A toy session pool: holds quiescent (bare, no armed op) connections waiting to
// be pulled onto another thread. Its mutex supplies the happens-before edge
// between the releasing worker and the adopting worker — the same role the global
// session-pool lock plays in ATS. This is the ONLY shared mutable state crossing
// threads for migration.
struct Pool {
  std::mutex                        mu;
  std::vector<CoroNetVConnection *> conns;

  void
  release(CoroNetVConnection *vc)
  {
    std::lock_guard<std::mutex> g(mu);
    conns.push_back(vc);
  }

  // Pull a pooled connection NOT currently owned by `self`, so the demo always
  // migrates across threads. owner() is read under the lock, after the releaser
  // pushed under the lock, so the read is safe.
  CoroNetVConnection *
  take_foreign(Reactor *self)
  {
    std::lock_guard<std::mutex> g(mu);
    for (auto it = conns.begin(); it != conns.end(); ++it) {
      if (&(*it)->owner() != self) {
        CoroNetVConnection *vc = *it;
        conns.erase(it);
        return vc;
      }
    }
    return nullptr;
  }
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

// Read one request and echo it back, allocating/freeing its own buffer so no
// buffer ever crosses the pool/migration boundary. Calls on_done after the echo
// is fully written.
void
echo_once(CoroNetVConnection *vc, std::function<void()> on_done)
{
  auto *buf = new Buf;
  vc->do_io_read(buf->data(), buf->size(), [vc, buf, on_done = std::move(on_done)](int ev) mutable {
    if (ev != VC_READ_READY && ev != VC_READ_COMPLETE) {
      delete buf;
      vc->do_io_close();
      return;
    }
    size_t n = vc->read_done();
    vc->do_io_write(buf->data(), n, [vc, buf, on_done = std::move(on_done)](int ev2) mutable {
      delete buf;
      if (ev2 == VC_WRITE_COMPLETE) {
        on_done();
      } else {
        vc->do_io_close();
      }
    });
  });
}

// Drive transaction 2 (and close) on whatever thread just adopted the connection.
void
serve_pooled_txn2(CoroNetVConnection *vc)
{
  echo_once(vc, [vc] { vc->do_io_close(); });
}

void
start_session(CoroNetVConnection *vc, bool pooled, Pool *pool)
{
  if (pooled) {
    // Transaction 1 here, then release the (now quiescent) connection into the
    // pool to be pulled onto another thread for transaction 2.
    echo_once(vc, [vc, pool] { vc->park_and_release([pool](CoroNetVConnection *v) { pool->release(v); }); });
  } else {
    // Two transactions on the owning thread, then close.
    echo_once(vc, [vc] { echo_once(vc, [vc] { vc->do_io_close(); }); });
  }
}

// ---- coroutines -------------------------------------------------------------

DetachedTask
accept_loop(Reactor &acc, int lfd, std::vector<Reactor *> *workers, Pool *pool, Stats *st)
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
    Reactor *w      = (*workers)[i % N_WORKERS];
    bool     pooled = (i == 0); // conn 0 is released to the pool and migrated
    ::printf("  acceptor(reactor %d): handed conn %d to worker reactor %d%s\n", acc.id(), i, w->id(),
             pooled ? " (will be pooled + migrated)" : "");
    // Create and drive the VC ON the worker thread.
    w->post_remote([w, cfd, i, pooled, pool, st] {
      auto *vc = new CoroNetVConnection(*w, cfd, i, [st] { st->server_done.fetch_add(1); });
      start_session(vc, pooled, pool);
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
  Pool                   pool;
  std::vector<Reactor *> workers(N_WORKERS, nullptr);
  std::atomic<Reactor *> acceptorR{nullptr};
  std::atomic<Reactor *> clientR{nullptr};
  std::atomic<int>       ready{0};

  // Worker threads: each constructs its own backend + reactor ON its thread, and
  // periodically scans the pool to adopt any connection released by another
  // worker (the destination-pull half of migration).
  std::vector<std::thread> worker_threads;
  for (int i = 0; i < N_WORKERS; ++i) {
    worker_threads.emplace_back([&, i] {
      auto    be = make_backend(which, i + 1);
      Reactor r(*be, i + 1);
      r.every(std::chrono::milliseconds(2), [&r, &pool] {
        if (CoroNetVConnection *vc = pool.take_foreign(&r)) {
          vc->migrate_here(r);   // synchronous adopt onto this thread
          serve_pooled_txn2(vc); // ...then drive the next transaction here
        }
      });
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
  ::printf("== coro-net MT prototype, backend = %s, %d workers, listening on 127.0.0.1:%u ==\n", which.c_str(), N_WORKERS, port);

  // Acceptor thread.
  std::thread acceptor_thread([&] {
    auto    be = make_backend(which, 0);
    Reactor r(*be, 0);
    acceptorR.store(&r);
    accept_loop(r, lfd, &workers, &pool, &st);
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
  while ((st.clients_done.load() < N_CONNS || st.server_done.load() < N_CONNS) && std::chrono::steady_clock::now() < deadline) {
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
