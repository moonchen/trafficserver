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

.. highlight:: cpp

.. _netvconnection-implementers-guide:

Implementing a NetVConnection
*****************************

.. RE: Split done as suggested: the generic contract (actor and turn
   model, VIO protocol, event vocabulary, buffers, locking, reentrancy,
   generic teardown, generic laws and pitfalls) moved to
   vconnection-implementers-guide.en.rst, and this page keeps the
   net-specific surface plus the reference implementation. The invariants
   page is untouched this round; generic INVs are cited from the
   VConnection page and the net-specific ones (INV-R3, INV-S1, INV-L3)
   from here. Splitting netvconnection-invariants.en.rst the same way is
   left open.

A ``NetVConnection`` is a ``VConnection`` over a network connection. The
contract it must uphold, the actor and turn model, the VIO channel
protocol, the event vocabulary and its firing conditions, the locking
geometry, the reentrancy discipline, and the teardown rules, is generic
and is stated in :ref:`vconnection-implementers-guide`; this page does not
repeat it. This page covers what networking adds: the surface
``NetVConnection`` layers over ``VConnection``, thread affinity, the
timeout machinery, and a walk through the reference implementation. The
rules of both pages are collected as a citable checklist, with stable
identifiers, in :ref:`netvconnection-invariants`; a parenthetical like
(INV-R3) refers to that page. Where this page and the code disagree, the
code wins; the reference implementation is
:ts:git:`src/iocore/net/UnixNetVConnection.cc`.

The class map is small. ``NetVConnection``
(:ts:git:`include/iocore/net/NetVConnection.h`) extends ``VConnection``,
with networking operations like the timeout setters and cancellers
(``set_inactivity_timeout``, ``set_active_timeout``, and their ``cancel_``
counterparts), the address accessors (``get_local_addr`` /
``get_remote_addr`` and their endpoint and port variants), the connection
options (the ``NetVCOptions`` member ``options``, pushed down by
``apply_options``), and the write-buffer trap (``trapWriteBufferEmpty``).
``UnixNetVConnection`` implements that surface over a socket, and a new
implementation stands in ``UnixNetVConnection``'s position, whether it
subclasses or starts from scratch.

The net-specific surface
========================

Besides the ``do_io_`` family and the ``reenable`` / ``reenable_re`` pair
inherited from ``VConnection``, an implementation supplies the
net-specific contract:

* Timeouts: ``set_inactivity_timeout`` / ``cancel_inactivity_timeout``
  and ``set_active_timeout`` / ``cancel_active_timeout``, with their
  getters. The semantics and the machinery behind them get their own
  section (`Timeouts`_).

* Addresses: ``get_local_addr`` / ``get_remote_addr`` and the endpoint
  and port variants, backed by the ``set_local_addr`` /
  ``set_remote_addr`` hooks; plus the connection context
  (``get_context``: ``NET_VCONNECTION_IN`` for a connection accepted from
  a client, ``NET_VCONNECTION_OUT`` for one opened to an origin).

* Options: the ``NetVCOptions`` member ``options`` holds the
  consumer-visible connection options, and ``apply_options`` pushes
  changed values down to the transport.

* The write-buffer trap: ``trapWriteBufferEmpty`` arms a one-shot event
  (``WRITE_READY`` by default) for the turn that empties the write
  buffer; the exact firing rule is with the rest of the write-turn
  mechanics (`The write turn`_).

Session-level code uses this surface directly: ``HttpSM`` reads the peer
and local addresses and the transport ``attributes`` off the VC and sets
the transaction timeouts on it, ``ProxySession`` holds its VC as a
``NetVConnection`` and replicates parts of this API toward the
transaction, and ``HttpTunnel`` arms the write-buffer trap on a
client-bound VC to get an unthrottle event after a small flow-control
window empties. The byte stream still moves only through the generic
``VConnection`` interface (:ref:`vconnection-implementers-guide`); the net
surface is control, not data.

Thread affinity
===============

A VC lives its whole life on one ``ET_NET`` thread, its home thread: every
turn, every delivery, every timeout, and its reclamation run there
(``free_thread`` release-asserts it). Thread confinement is the net
module's serialization strategy and the reason the per-direction state
needs no per-VC lock, so the affinity is not advice; it is the concurrency
model (INV-L3).

The binding starts at creation, and the creation is itself a message: the
accept path sets the new VC's handler to ``acceptEvent`` and schedules it
to the assigned net thread, where its first turn registers the socket with
that thread's poll machinery and delivers ``NET_EVENT_ACCEPT``. The
connect path runs on the net thread from the start and hands the VC to the
caller with ``NET_EVENT_OPEN`` as soon as the nonblocking connect is
issued: the caller is an actor and cannot wait out a handshake, so success
or failure surfaces later through the ordinary event vocabulary on the
VIOs.

Turns never run off-thread. The one routine cross-thread call is
``reenable``: a consumer whose mutex is held on a foreign thread may call
it, and the foreign thread only records facts under the right locks. The
names in the rest of this section belong to the reference machinery,
walked fully in `NetEvent and the NetHandler cycle`_: each net thread
runs one ``NetHandler``, the scheduler that converts poll readiness into
turns; its per-direction ready lists hold the VCs owed a turn; its atomic
enable list receives facts recorded by foreign threads; and a
per-direction ``triggered`` flag records that the transport announced
progress. The stock ``reenable`` marks the direction enabled under the
consumer's mutex, then tries the home ``NetHandler``'s mutex and updates
the ready list under it, or, when the try-lock fails, pushes the VC onto
an atomic enable list and wakes the home thread (``signalActivity``),
which drains the list at the top of its next cycle
(``process_enabled_list``). Either way the recorded fact is a message;
the turn it provokes runs only on the home thread. Any request an
implementation must accept from off-thread follows the same shape: record
a fact, wake the owner, return.

The per-direction state is accordingly split across three locking
regimes: the ``enabled`` flags are written under the VIO's mutex
(``set_enabled`` asserts it, and that is what makes a foreign-thread
reenable safe); ready- and enable-list membership changes under the
``NetHandler``'s mutex or through its atomic enable list; ``triggered``
and the turns themselves belong to the home thread alone.

An implementation must not move a VC between threads by mutation. The one
sanctioned move, ``migrateToCurrentThread``, builds a new VC around the
same transport on the target thread and closes the old one; it is a
handoff between actors, not a migration of one.

Timeouts
========

A stalled flow generates no transport events, so timeouts are the safety
net, and they arrive as messages like everything else, on the VC's own
mailbox. An implementation supports both timeout types of the
``NetVConnection`` interface
(:ts:git:`include/iocore/net/NetVConnection.h`):

* The inactivity timeout fires when an enabled operation makes no progress
  for the configured period. An implementation resets the deadline on any
  transferred byte (the stock turn functions call ``netActivity()`` after
  moving data) and on ``set_inactivity_timeout``, arms it, if it is not
  already armed, when an operation is enabled, and clears it when both
  directions are disabled, so that an idle-by-design connection is not
  falsely reaped (the stock ``read_disable`` / ``write_disable`` clear the
  deadline when the opposite direction is already disabled). When the
  consumer sets no inactivity timeout, the sweep applies
  :ts:cv:`proxy.config.net.default_inactivity_timeout` as a backstop to
  any VC with an enabled operation.

* The active timeout bounds the total lifetime of the connection
  regardless of progress, armed by ``set_active_timeout``.

The stock mechanism is as follows: the VC stores deadlines, and a
per-thread sweep continuation (``InactivityCop``,
:ts:git:`src/iocore/net/UnixNet.cc`) scans the thread's open VCs once per
:ts:cv:`proxy.config.net.inactivity_check_frequency` seconds and, for each
expired deadline, delivers ``VC_EVENT_INACTIVITY_TIMEOUT`` or
``VC_EVENT_ACTIVE_TIMEOUT`` to the VC itself, under the VC's own mutex
(try-lock; a busy VC is retried on the next sweep, so contention defers
the message and never blocks the sweep). The VC's handler
(``UnixNetVConnection::mainEvent``) then relays the event to its
consumers: it takes the read and write VIO mutexes (try-lock; on
contention it returns and the undisturbed deadline retries next sweep),
zeroes the deadline, signals the read consumer, and signals the write
consumer only if it is a different continuation; one actor gets one
message per fact.

Two consequences follow for an implementer. First, the VC must keep a
handler installed for these deliveries at all times; the timeout path is a
normal message to the VC actor and follows every delivery rule of the
generic guide. Second, the ``set_`` / ``cancel_`` timeout calls are
unsynchronized state on the VC, and the interface restricts them to code
handling an event delivered from the VC, or the creation delivery; they
must not be called from elsewhere.

On close, the timeout machinery is withdrawn at reclamation:
``free_netevent`` removes the VC from the sweep's lists before the memory
is reused, and a sweep that finds an already-closed VC frees it rather
than signaling it. Nothing fires after close.

Walking the reference implementation
====================================

.. RE: NetEvent is gone from the intro and the surface sections, and the
   full NetEvent/NetHandler treatment lives only in this section, as the
   machinery that facilitates epoll/kqueue readiness for the socket
   implementation, not as part of the NetVConnection contract. Thread
   affinity still names NetHandler, the ready/enable lists, and triggered
   for its locking regimes, with a one-sentence gloss on first use and a
   forward pointer here. A standalone UnixNetVConnection doc remains an
   option; this section is written so it could be lifted out wholesale.

``UnixNetVConnection`` (:ts:git:`src/iocore/net/P_UnixNetVConnection.h`)
is the reference implementation: every rule in this guide and the generic
one is a few lines in it. The subsections below name the machinery a
reader meets there and the seams a new transport would override.

NetEvent and the NetHandler cycle
---------------------------------

``NetEvent`` (:ts:git:`include/iocore/net/NetEvent.h`) is not part of the
``NetVConnection`` contract. It is a separate interface, the one the
per-thread scheduler, ``NetHandler``, calls to run readiness-based
sockets over epoll or kqueue; ``UnixNetVConnection`` implements both
interfaces and joins them over a socket. ``NetEvent``'s pure virtuals are
the turns themselves (``net_read_io`` / ``net_write_io``), reclamation
(``free_thread``), and a handful of accessors and timeout hooks that the
scheduler and the timeout sweep (`Timeouts`_) need; its concrete members
are the state the rules on this page name: one ``NetState`` per direction
(the ``VIO``, the ``enabled`` and ``triggered`` flags, the ready- and
enable-list links), the ``closed`` flag, the latched socket ``error``, and
the timeout deadlines. An implementation on this substrate must use these
members rather than invent parallel ones. (``lerrno`` comes from
``VConnection``; the ``recursion`` counter is ``UnixNetVConnection``'s
own.)

Each net thread runs one ``NetHandler``, and each cycle of it
(``NetHandler::waitForActivity``, :ts:git:`src/iocore/net/NetHandler.cc`)
first drains an atomic enable list of cross-thread reenables
(``process_enabled_list``), then polls the transport and records each
readiness announcement in the owning direction's ``triggered`` flag, then
walks the read and write ready lists (``process_ready_list``), giving one
turn to every VC that is both ``enabled`` (the consumer wants progress)
and ``triggered`` (the transport announced some). A read turn is one call
to ``net_read_io`` and a write turn is one call to ``net_write_io``; those
turns are where bytes move and events are delivered.

A transport that changes how bytes move over the same socket-and-poll
substrate subclasses ``UnixNetVConnection`` and overrides the byte-moving
seams (``net_read_io``, ``load_buffer_and_write``, and the protocol-setup
pair ``_isReadyToTransferData`` / ``_beReadyToTransferData``); a transport
that replaces the substrate implements both interfaces itself. A subclass
inherits the stock mechanisms below, and a substrate replacement supplies
its own without changing what the consumer observes (INV-C1).

The delivery helpers
--------------------

The top of :ts:git:`src/iocore/net/UnixNetVConnection.cc` defines six
file-local helpers, and the entire delivery discipline of the generic
guide is these six functions: ``read_reschedule`` / ``write_reschedule``
requeue the VC on the ready list iff ``triggered && enabled``;
``read_signal_and_update`` / ``write_signal_and_update`` wrap every
delivery with the recursion counter and the
``vio.mutex == vio.cont->mutex`` check, and free the VC when a close was
requested mid-signal; ``read_signal_done`` / ``write_signal_done`` clear
the enable before a completing or terminal delivery. The unwind that
grants a deferred close appears in ``read_signal_and_update`` verbatim:

.. code-block:: cpp

   if (!--vc->recursion && vc->closed) {
     /* BZ  31932 */
     ink_assert(vc->thread == this_ethread());
     vc->nh->free_netevent(vc);
     return EVENT_DONE;
   } else {
     return EVENT_CONT;
   }

The read turn
-------------

``net_read_io`` is one read turn: try the consumer's lock or requeue;
check the gates (``closed`` first, freeing the VC instead of signaling,
then enablement and ``ntodo``); read at most the buffer's free space in a
drain loop; ``fill`` the buffer and advance ``ndone``; signal; then
re-read the shared state and choose disable, requeue, or return. The net
firing conditions of the generic event vocabulary live here:

* ``READ_READY`` after new bytes are in the buffer, at most once per
  turn; ``READ_COMPLETE`` through ``read_signal_done`` when ``ntodo``
  reaches zero.

* ``EOS`` when ``recvmsg`` returns zero or fails with ``ECONNRESET``,
  delivered through ``read_signal_done`` in place of ``READ_READY``.

* The would-block family (``EAGAIN``, ``ENOTCONN``) is not an event: it
  ends the drain, clears ``read.triggered`` (the edge is consumed), and
  leaves the ready list.

* Any other ``recvmsg`` failure stores the errno in ``lerrno`` and
  delivers ``ERROR`` through the same disable-first path.

The write turn
--------------

``net_write_io`` is one write turn, and it is where the demand-driven
write contract (INV-W1) is discharged. In order: try the consumer's lock
or requeue; deliver a latched socket ``error`` as ``ERROR`` if the poll
machinery reported one; run the protocol-setup seam (below); check
enablement and ``ntodo``; then move bytes and signal. The stock firing
points of ``WRITE_READY`` are exact:

* at the top of the turn, topping up before the drain, when the buffered
  bytes do not cover the remainder of the operation and the buffer stands
  at or below its water mark (``!high_water()``);

* after the drain, when no request was made at the top of the turn, or
  when the buffer stands at or below the water mark and the operation is
  still unfinished.

One narrower source exists besides these: the one-shot
``trapWriteBufferEmpty`` event is delivered on the turn whose drain
empties the buffer, and only if that turn delivers no ordinary post-drain
event.

The drain itself is ``load_buffer_and_write``, the byte-moving seam a
subclass overrides; ``ndone`` advances by what ``sendmsg`` accepted, and
``WRITE_COMPLETE`` goes through ``write_signal_done`` when the final byte
of the operation is accepted into the kernel. A would-block clears
``write.triggered``; any other ``sendmsg`` failure also clears it, then
delivers ``ERROR`` after storing the errno. The poll-reported socket
error is different in shape: it is latched in the VC's ``error`` field
and re-checked at the top of every write turn, before any other gate;
that path leaves the direction enabled, and the enabled direction is what
re-delivers the latched state. These are the two error shapes the generic
guide names: disable and deliver once, or latch and keep delivering.

When the drain leaves the buffer empty, the turn disables the write:
``write_disable`` clears the enable and leaves the ready list. (It also
calls ``ep.modify(-EVENTIO_WRITE)``, but that call is vestigial: the
stock builds are edge-triggered, ``EventIO::modify`` compiles to a no-op,
and poll interest, registered once as ``EVENTIO_READ | EVENTIO_WRITE`` in
``NetHandler::startIO``, is never withdrawn.) ``write.triggered`` is not
cleared here; it clears only when the edge is consumed, on a would-block
or a terminal delivery in its place. The consequence is the deadlock rule
stated with ``WRITE_READY`` in the generic guide: once the write is
disabled on an empty buffer, room in the socket's send buffer cannot wake
the VC, because a ready-list turn requires ``enabled && triggered`` and
an edge-triggered kernel never re-announces standing room; the consumer's
``reenable`` is the only resume. After a ``reenable``, a still-set
``triggered`` gives the VC a turn on the current cycle, and a cleared one
leaves the VC armed for the kernel's next full-to-writable transition.

Readiness must survive backpressure
-----------------------------------

The stock poll registration is edge-triggered: the kernel announces a
socket's transition once, and the announcement is consumable exactly once.
The turn therefore loops until a short read or ``EAGAIN`` says the socket
is drained; stopping early would strand bytes the kernel considers
announced. That drain spans turns rather than one call: a turn reads at
most the buffer's free space, and ``read_reschedule`` keeps a VC whose
announced progress is not yet consumed on the ready list, which the same
``NetHandler`` cycle keeps walking. The announcement is recorded in the
per-direction ``triggered`` flag that is cleared only when the edge has
been consumed (drained to ``EAGAIN``, or a terminal event delivered in its
place), never when the turn stops early because the buffer is full
(INV-R3). That persistence is what makes ``reenable`` sufficient to resume
a disabled producer: the fact that the transport announced progress is
still recorded.

The same persistence carries the read side's terminal state. The stock
implementation holds no EOF flag; it relies on two facts: disabling does
not clear ``triggered``, so the announcement that carried the end of
stream stays recorded and a later ``reenable`` still receives a turn; and
that turn re-reads the EOF from the transport. That is how an undelivered
end of stream survives the operation being disabled (INV-R5). Once the
event is delivered, the announcement has been consumed: the direction is
disabled, and the stock VC does not raise ``EOS`` again for a consumer
that attaches or reenables afterward; such a consumer waits without events
until the inactivity backstop reaps the connection.

The rules above are phrased in the stock substrate's terms: an
announcement that I/O may be attempted, and an attempt that discovers how
much. A transport whose primitive is the completed transfer rather than a
notification that an attempt may succeed carries the same obligations
under an inverted mapping: a completion not yet delivered into the
operation's buffer is the readiness fact, delivering those bytes and
advancing ``ndone`` consumes it, disabling is declining to issue the next
transport operation, and ``reenable`` is what issues it. The invariant
does not move: the VC never goes idle without the fact preserved, a
transport operation still outstanding, or a peer guaranteed to reenable it
(INV-R3), and a transport operation still in flight holds the VC and its
buffer views for teardown purposes (INV-L2).

Protocol setup runs before the consumer gates
---------------------------------------------

A transport that must negotiate before it can carry consumer data, a TLS
handshake being the model, carries a setup obligation (INV-S1): protocol
setup runs on every transport event, in either direction, whether or not a
consumer has attached or enabled a VIO, because the consumer-VIO gates
govern post-setup delivery only. Arrived handshake bytes sit buffered in
the transport, and nothing re-signals buffered data (INV-R2), so a setup
gated behind a consumer VIO strands the handshake until a timeout reaps
the connection. The stock write turn therefore runs the protocol-setup
pair (``_isReadyToTransferData`` / ``_beReadyToTransferData``) ahead of
the enablement and ``ntodo`` gates on the consumer's operation, and a
handshaking subclass relies on that ordering.

Teardown on the net path
------------------------

The close contract is in :ref:`vconnection-implementers-guide`; these are
the stock mechanisms that discharge it. ``do_io_close`` computes whether
it may free inline as follows:

.. code-block:: cpp

   EThread *t            = this_ethread();
   bool     close_inline = !recursion && (!nh || nh->mutex->thread_holding == t);

Otherwise the deferred-reaper rule of the generic guide applies; the
stock reapers are the outermost delivery helper (the unwind excerpt
above) and the home thread's list walks and timeout sweep. The ready-list
walk and the read turn observe the ``closed`` flag and free the VC
instead of signaling; closed VCs never reach the write turn because the
walk frees them first.

Reclamation is ``free_netevent`` (:ts:git:`src/iocore/net/NetHandler.cc`):
it removes the VC from the timeout sweep, the poll set, and the ready and
enable lists, then returns the memory to its allocator (``free_thread``).
The order is the point: everything that could still deliver into the VC is
disconnected before the memory can be reissued. For the stock socket VC
the only attachment that outlives a turn is the poll registration, and
``free_netevent`` severs it; a transport whose operations remain in flight
in the kernel after a turn must also cancel them and observe the
cancellation on every free path before the memory is reused (INV-L2).

A reading order
---------------

#. :ts:git:`include/iocore/eventsystem/VConnection.h` and
   :ts:git:`include/iocore/eventsystem/VIO.h`: the contract surface and
   the channel's shared descriptor, with the interface documentation.

#. The top of :ts:git:`src/iocore/net/UnixNetVConnection.cc`: the six
   file-local delivery helpers.

#. ``net_read_io`` and ``net_write_io`` in the same file, one turn each.

#. ``reenable`` and ``reenable_re``: disabling and resumption, the
   cross-thread enable list, and the recursive variant's synchronous turn;
   with ``NetHandler::waitForActivity``, ``process_enabled_list``, and
   ``process_ready_list`` (:ts:git:`src/iocore/net/NetHandler.cc`) for the
   cycle that converts readiness into turns.

#. ``do_io_close``, ``mainEvent``, and ``free_thread`` in
   :ts:git:`src/iocore/net/UnixNetVConnection.cc`, with ``free_netevent``
   (:ts:git:`src/iocore/net/NetHandler.cc`) and ``InactivityCop``
   (:ts:git:`src/iocore/net/UnixNet.cc`): teardown, timeout delivery, and
   the deferred reapers.

The laws
========

The generic laws are in :ref:`vconnection-implementers-guide`. Reviews can
cite these net-specific ones by number:

#. An implementation must consume the whole readiness fact: it drains to
   would-block or buffer-full, and it preserves the fact while a direction
   is disabled under backpressure.

#. Protocol setup runs on every transport event, in either direction,
   ahead of the consumer's enablement and ``ntodo`` gates; a consumer VIO
   gates post-setup delivery only.

#. Off-thread means scheduled: a foreign thread may enqueue a fact and
   wake the owner; only the home thread runs turns.

#. A VC is reclaimed on its home thread, and only after every event
   source, the timeout sweep, the poll set, and the ready and enable
   lists, is withdrawn.

Pitfalls
========

The generic pitfalls table is in :ref:`vconnection-implementers-guide`;
these are the net-specific rows.

+------------------------------+----------------------------------------------+
| Symptom                      | Where to look                                |
+==============================+==============================================+
| Consumer never wakes;        | A backpressure stop cleared ``triggered`` so |
| transfer stalls until a      | a later reenable found nothing to resume;    |
| timeout                      | the readiness fact must survive a disable    |
|                              | (INV-R3).                                    |
+------------------------------+----------------------------------------------+
| Write side never wakes       | The write was disabled when its buffer       |
| though the socket can        | emptied, and a ready-list turn requires      |
| accept more                  | ``enabled && triggered``; room is a state,   |
|                              | not an event, and only the consumer's        |
|                              | ``reenable`` resumes the direction.          |
+------------------------------+----------------------------------------------+
| Idle-by-design connection    | The inactivity deadline stayed armed while   |
| reaped                       | both directions were disabled; the stock     |
|                              | disable helpers clear it when the opposite   |
|                              | direction is already disabled.               |
+------------------------------+----------------------------------------------+
