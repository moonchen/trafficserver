.. Licensed to the Apache Software Foundation (ASF) under one
   or more contributor license agreements.  See the NOTICE file
   distributed with this work for additional information
   regarding copyright ownership.  The ASF licenses this file
   to you under the Apache License, Version 2.0 (the
   "License"); you may not use this file except in compliance
   with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing,
   software distributed under the License is distributed on an
   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
   KIND, either express or implied.  See the License for the
   specific language governing permissions and limitations
   under the License.

.. include:: ../common.defs

.. _netvconnection-invariants:

NetVConnection Invariants
*************************

A :class:`NetVConnection` is the proxy's unit of transport: it exposes
``do_io_read`` / ``do_io_write`` / ``do_io_close`` plus a ``Continuation``/VIO
event interface, and the entire proxy (HttpSM, HTTP/2, tunnels, transforms) is
written against *only* that interface, independent of how bytes actually move
(plain TCP via epoll, TLS over an inner VC, io_uring, ...). That independence is
real only if every transport implementation upholds the same behavioural
contract.

This document collects that contract as a checklist of **invariants**. Each was
either codified by the framework from the start or learned the hard way --- most
of the read/write/lifecycle invariants were extracted while debugging the
layered TLS VConnection refactor and the io_uring NetVConnection port. It is a
*living*
document: when a new invariant is discovered (ideally because a bug proved it),
append it here with the code path and the failure it prevents.

The mental model
================

Every read flow is a chain of producer -> buffer -> consumer stages. The socket
:class:`NetVConnection` is the first producer; HttpSM / HTTP/2 / tunnel /
transforms are consumers (and often producers for the next stage). Writes run
the same chain in reverse. **Liveness depends on who is responsible for
re-waking a stalled stage**, and the framework pushes most of that onto the
*consumer* by convention: the core re-signals a consumer only when the producer
moves *new* bytes, never for bytes already sitting in a buffer.

A transport implementation that breaks one of these invariants usually does not
fail loudly. It stalls one flow, under one workload, until a timeout --- so the
invariants below double as a code-review checklist for any new or modified VC.

The contract surface
====================

.. rubric:: INV-C1 --- the ``do_io_*`` + VIO + ``Continuation`` facade is identical for every transport

Callers see the same VIO state machine (``READ_READY`` / ``READ_COMPLETE`` /
``WRITE_READY`` / ``WRITE_COMPLETE`` / ``EOS`` / ``VC_EVENT_ERROR`` /
timeouts) regardless of transport. A transport may change *how* bytes move but
must not change *which* events fire, in what order, or with what VIO/buffer
state. Swapping a transport in (io_uring, TLS) must be invisible above this line.

.. rubric:: INV-C2 --- a VIO is signalled only while its mutex is held

To call ``vio.cont->handleEvent(...)`` you must hold ``vio.mutex`` (it is the
consumer continuation's mutex). The producer takes it with ``MUTEX_TRY_LOCK``
and reschedules itself if it cannot get it. Holding it also makes the
signal-to-free re-entrancy bookkeeping (INV-L1) correct, because the consumer's
callback runs under the same lock.

Read path
=========

.. rubric:: INV-R1 --- the consumer must drain every COMPLETE unit on each READ_READY

On every ``VC_EVENT_READ_READY`` a read consumer must consume *every complete
unit of progress* in the buffer (loop until less than one unit remains); leaving
a trailing *partial* unit is fine. A "unit" is the most bytes one consumer step
needs: a full header block, a full TLS record (<=16K), an HTTP/2 frame
header(+payload), etc. **Why:** a fresh ``READ_READY`` arrives only when the
producer reads *new* socket bytes; the framework never re-signals for data
already buffered. A complete unit left behind strands until more socket data
happens to arrive --- and if the buffer is also full, the producer disabled
itself on ``!write_avail()`` and can never re-fill: hard deadlock. *Proven by*
``SSLNetVConnection::_trigger_ssl_read`` delivering one TLS record per call.

.. rubric:: INV-R2 --- reenable re-drives the PRODUCER; buffered data is never re-signalled

Reenabling a read VIO reschedules the *producer* NetVC; it does not re-deliver
already-buffered bytes to the consumer. A consumer must therefore act on the
bytes it can see while it holds the current signal (INV-R1); it cannot assume
"I'll be signalled again" for data already in its input buffer.

.. rubric:: INV-R3 --- the producer must fully drain its readiness signal before yielding it

The net poll set is edge-triggered (``EPOLLIN | EPOLLET``): the kernel reports
readability once per edge. The epoll producer (``net_read_io``) therefore reads
in a loop until a short read / ``EAGAIN`` (socket drained) or the read buffer is
full (backpressure) --- a single read per edge would strand readable bytes with
no further notification. ``read.triggered`` persists across a backpressure
``read_disable`` (it is cleared only on ``EAGAIN``); when the consumer drains and
reenables, ``read_reschedule`` (``triggered && enabled``) re-drives the producer
into the freed space. That persistence is the *only* thing that resumes a
producer stopped on a full buffer.

The **io_uring** transport faces the same requirement for the same reason: a
completion-driven recvmsg must *drain the socket per readiness edge* (loop
recvmsg until a short read / full buffer / VIO satisfied) before yielding back to
epoll, or it strands bytes identically. This was proven during the port: a first
cut that issued one recvmsg per trigger stalled a large body (``curl`` partial
transfer + multi-second hang) until the drain loop was added.

.. rubric:: INV-R4 --- a stage that is both consumer and producer must SELF-DRIVE its input

A VC that consumes an input buffer and produces into a downstream buffer (a TLS
layer decrypting into plaintext, any transform) must, on each drive, drain its
input up to the downstream's capacity *or* schedule its own continuation to
finish --- it must not rely on its upstream to "wake me for buffered input",
because the upstream only re-signals on new *external* bytes (INV-R2). For a
layered TLS VC: after freeing downstream room, if the read BIO still holds
ciphertext, schedule an off-stack read drive rather than reenabling the
transport read.

.. rubric:: INV-R5 --- EOS / ERROR is a persistent STATE, not an edge

Once the transport is closed or errored it will not signal again. On a plain
socket VC the state lives in the socket itself: every enabled read pass re-reads
the EOF/error and re-delivers ``EOS`` / ``VC_EVENT_ERROR`` (``read.triggered``
persists; a consumer that does not want it disables its read). A VC that instead
records terminal state in a flag must reproduce that persistence: deliver the
terminal event whenever the user read is enabled and intermediate buffers are
drained, and *re-drive* delivery when a consumer attaches (``do_io_read``) or
reenables later. **Never unconditionally suppress** a terminal signal for one
consumer scenario --- the suppression outlives the scenario and strands every
other consumer (*proven by* an inbound half-close "quiesce" that suppressed EOS
for all bare-FIN closes and wedged idle keep-alive teardown).

Write path
==========

.. rubric:: INV-W1 --- the write path is demand-driven; do not encrypt/produce ahead of the transport

When the user reenables its write VIO, do not eagerly consume all available
plaintext. Producing ahead of the socket's ability to send grows the staging
buffer toward the size of the whole response and severs end-to-end backpressure
(the user's write "completes" at memory speed and keeps producing). Re-arm the
transport write and produce only on the transport's ``WRITE_READY``; bound any
staging buffer with a water mark.

.. rubric:: INV-W2 --- WRITE_COMPLETE is delivered OUT OF LINE

The consumer typically closes the connection from its ``WRITE_COMPLETE``
handler. If the final bytes may still be buffered/in flight when the producing
call returns, ``WRITE_COMPLETE`` must be scheduled (delivered off the current
stack), not signalled inline: an inline signal while the transport's write path
is still on the stack and still references the staging buffer lets the consumer's
close truncate the response or free a buffer still in use. Deliver
``WRITE_COMPLETE`` only once the bytes have actually drained to the transport.

Buffers
=======

.. rubric:: INV-B1 --- a MIOBuffer grows only below its high-water mark

``MIOBuffer::write_avail()`` adds a block only when ``!high_water() &&
current_low_water()``, where ``high_water()`` compares ``max_read_avail()`` (the
**max over all readers**) against ``water_mark``. Consequences: with
``water_mark == 0`` any unconsumed byte makes ``high_water()`` true, so the
buffer cannot grow past its current block until fully drained; and a second or
leaked reader pinned at the head keeps ``max_read_avail()`` high and wedges
growth forever. A buffer that is both a read target and must hold more than one
block of unconsumed data needs a non-zero ``water_mark``, and every
``alloc_reader()`` on it must be advanced or freed promptly.

Protocol setup (layered transports)
===================================

.. rubric:: INV-S1 --- protocol setup must not be gated on consumer-VIO state

A layered/wrapped VC must drive its protocol setup (e.g. a TLS handshake) for
every transport event, on both faces, regardless of whether a consumer has
attached or enabled a user VIO --- consumer-VIO gates govern *post-setup* data
delivery only. With an intermediate read buffer the read face is the only
deliverer of arrived handshake bytes (INV-R2: nobody re-signals buffered data),
so gating it on a user VIO strands the handshake until a timeout. The setup
branch must run before any "no consumer VIO -> disable transport + return" gate,
and zero-length-VIO completion probes must be guarded so a missing consumer is
not signalled.

Object lifecycle and re-entrancy
================================

.. rubric:: INV-L1 --- a close from inside a user signal must defer the free

A user event handler may call ``do_io_close`` from within its callback (closing
on ``WRITE_COMPLETE`` is the common case). The VC must track signal re-entrancy
depth and, if it is closed while a signal is still on the stack, defer the actual
free until the outermost signal unwinds; it may free inline only when no signal
is in progress. On the plain socket VC this is the ``recursion`` counter around
``read_signal_and_update`` / ``write_signal_and_update`` together with
``close_inline = !recursion && ...`` in ``do_io_close``.

.. rubric:: INV-L2 --- an async transport must cancel-then-unwind, never free with an op in flight

When the transport's I/O is asynchronous (io_uring SQEs in the kernel, an async
handshake), an in-flight operation holds a pointer into the VC (or into a
coroutine frame that references the VC). Freeing the VC while that op is
outstanding is a use-after-free when the completion later fires. ``do_io_close``
must instead cancel the in-flight op and defer teardown until the (cancelled)
completion is observed, then free. *Proven by* the original net-iouring branch's
``do_io_close`` doing ``delete this`` with a recvmsg still in the ring.

.. rubric:: INV-L3 --- a NetVConnection is thread-confined; cross-thread moves go through one serialized channel

A VC lives on one ``ET_NET`` thread for its lifetime; its I/O completes and its
continuation runs on that thread, so the resume path needs no per-VC lock on the
hot path. The few legitimate cross-thread events go through explicitly
synchronized channels only: the accept hand-off, and global-session-pool
migration (``migrateToCurrentThread``), which is serialized by the pool mutex
that the acquiring thread holds across the whole move so the origin thread cannot
touch the VC concurrently. Nothing else may touch a VC from another thread.

How the io_uring NetVConnection honors these
============================================

:class:`IOUringNetVConnection` (``src/iocore/net/IOUringNetVConnection.{h,cc}``,
gated by ``proxy.config.net.io_uring.enabled``) is a :class:`UnixNetVConnection`
subclass that swaps individual I/O seams to io_uring while inheriting the rest.
Status of each invariant for the current (read-path) state:

.. list-table::
   :header-rows: 1
   :widths: 12 12 76

   * - Invariant
     - Status
     - How / where
   * - INV-C1
     - held
     - Inherits the base ``do_io_*`` / VIO facade; only ``net_read_io`` and
       ``do_io_close`` are overridden.
   * - INV-C2
     - held
     - ``_read`` takes ``read.vio.mutex`` before fill + signal.
   * - INV-R1
     - n/a
     - Consumer-side; this VC is the producer.
   * - INV-R2
     - held
     - Inherited; reenable re-drives via ``net_read_io``.
   * - INV-R3
     - held
     - ``_read`` drains the socket per epoll edge (loops recvmsg until a short
       read / full buffer / VIO satisfied).
   * - INV-R4
     - n/a
     - Plain VC is not a transform (relevant once TLS layers on top).
   * - INV-R5
     - partial
     - EOS / EAGAIN / ERROR handled per read; relies on the inherited epoll
       re-trigger. Re-verify if the read path stops using the epoll trigger.
   * - INV-W1
     - inherited
     - Write still uses the base (epoll) path.
   * - INV-W2
     - inherited
     - Write still uses the base path; revisit when the write path moves to
       io_uring sendmsg.
   * - INV-B1
     - held
     - Inherited; ``_read`` honors ``write_avail()`` and stops on a full buffer
       (backpressure via ``read_disable`` + base reenable).
   * - INV-S1
     - n/a
     - Not a layered VC yet.
   * - INV-L1
     - held
     - Reimplements the ``recursion`` / ``closed`` contract
       (``_read_signal_and_update`` / ``_read_signal_done``) because the base
       helpers are file-static.
   * - INV-L2
     - held
     - ``do_io_close`` cancels the in-flight recvmsg and defers the free to the
       resuming read coroutine.
   * - INV-L3
     - held
     - One ring per EThread (``thread_local``), so a recvmsg CQE drains and
       resumes on the submitting thread; no per-VC mutex added. Migration not
       yet supported.

Type-structuring guidance
=========================

The invariants above are behavioural; several can be made harder to violate by
structuring the io_uring/coroutine types so the dangerous state is difficult to
express. Guidelines used (and to keep using) in this port:

* **Pin the awaitable; forbid relocation.** A ``UringOp`` *is* the SQE's
  ``user_data``; if it moved after submission the kernel would write to a stale
  address. The type is therefore non-copyable and non-movable, and it lives in
  the coroutine frame (a ``co_await`` temporary or a named local), so its address
  is stable for exactly the op's lifetime. Buffer lifetime rides the same frame
  pin --- no class-scope ``msghdr`` hoisting, no per-op heap churn. Encoding this
  in the type is what makes INV-L2's "the op references live storage" true by
  construction.

* **Make "free with an op in flight" representable only as the deferred path.**
  The in-flight op is tracked by a single ``IOUringCompletionHandler*`` that is
  non-null *iff* a recvmsg is actually outstanding; ``do_io_close`` keys off it
  to choose cancel-then-defer vs. free-inline. A future cleanup could fold this
  into one RAII "in-flight op" guard that registers on submit and cancels on
  early destruction, so a teardown path cannot forget to cancel.

* **Keep the coroutine the single owner of the drive loop.** The read drive
  (drain loop, fill, signal, re-arm) lives entirely inside one coroutine, so the
  state machine is straight-line code rather than flags reconstructed across
  callbacks. The teardown rule reduces to one precondition ("only free once no op
  is in flight"), enforced at the one ``co_await`` resumption point.

* **Don't reach for a per-VC mutex.** Thread confinement (INV-L3), not a lock, is
  the serialization mechanism; the only lock taken is the consumer's
  ``vio.mutex``, and only to satisfy INV-C2 when signalling. A debug-only
  "assert on owner thread" at resume points documents and enforces the
  confinement instead of a lock.

* **Name members defensively against C macros.** ``UringOp::_res`` had to become
  ``_result`` because glibc ``<resolv.h>`` ``#define``\ s ``_res``; the macro is
  pulled in transitively the moment the header is used from the net layer. Prefer
  member names that are not common POSIX/libc macro identifiers (``_res``,
  ``_sys``, ``stat``, ``major`` ...).

* **Respect the "destroy only when done" precondition on owned coroutines.**
  An owned ``Task`` must not be destroyed while its coroutine is suspended on an
  in-flight op (that frees the awaitable the kernel still references). Drive to
  ``done()`` --- or cancel-then-unwind --- first. This is documented on ``Task``
  and is the owned-coroutine analogue of INV-L2.

.. note::

   This file is maintained alongside the io_uring networking work. When a leaf of
   the net path is converted (write, accept/connect, TLS), update the status
   table above and add any newly discovered invariant with the bug that proved
   it.
