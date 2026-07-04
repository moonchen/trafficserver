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

.. _vconnection-implementers-guide:

Implementing a VConnection
**************************

A ``VConnection`` is an actor mediating between a byte stream and a
consumer. An actor, in the sense used throughout this page, is an object
with isolated state that interacts with the rest of the system only by
exchanging messages and that processes one message at a time; one such
processing step is called a turn. The VC owns one end of the byte stream
and speaks the VIO channel protocol, moving bytes between the stream and a
bounded, shared buffer while reporting progress to the consumer as events.
The consumer never reads or writes the underlying stream. It controls
operations (``do_io_read`` / ``do_io_write``), each of which remains in
effect across arbitrarily many transfers, and exchanges messages with the
VC about them; the ``VIO`` returned by each call is the operation's
descriptor. This page is a guide for the implementer: it states every
obligation a new ``VConnection`` class has, some reasoning behind them.

The thread and event machinery underneath is described in
:ref:`threads-and-events`. The rules below are collected as a citable
checklist, with stable identifiers, in :ref:`netvconnection-invariants`; a
parenthetical like (INV-R2) refers to that page. Where this page and the
code disagree, the code wins. The interface is
:ts:git:`include/iocore/eventsystem/VConnection.h`; the fully worked
reference implementation is the socket VC, walked in
:ref:`netvconnection-implementers-guide`, and this page points there where
an obligation is easiest to see in code.

The contract seen from the consumer
===================================

The consumer calls ``do_io_read(c, nbytes, buffer)`` to ask for up to
``nbytes`` bytes delivered into ``buffer``, calls
``do_io_write(c, nbytes, reader)`` for the write-side counterpart, and
receives a ``VIO`` handle (:ts:git:`include/iocore/eventsystem/VIO.h`) for
each operation. The VIO records the continuation ``c`` as ``vio.cont``, the
name used for it throughout this page; every progress event is delivered to
``vio.cont``. The VIO carries the operation's shared state: ``nbytes`` is
the size of the operation, ``ndone`` the bytes moved so far, and
``ntodo()`` the remainder; the consumer and the VC both read and update
these fields under one mutex, the consumer's own (`Locking geometry`_). An
operation that can make no progress becomes disabled and stops receiving
scheduler attention until the consumer resumes it with ``VIO::reenable``;
the consumer ends both operations with ``do_io_close``.

Byte-stream traffic flows through this interface alone: ``HttpSM``,
sessions (:ref:`client-session-architecture`), tunnels, transforms, and
plugins move bytes and observe progress only through the ``do_io_``
operations, the VIO, and the events below. The independence is scoped to
the byte stream, not to the whole object. Code that owns a connection knows
which concrete class it holds and uses that class's wider surface;
``HttpSM`` sets timeouts and reads addresses on its ``NetVConnection``, and
the session classes wrap that same surface
(:ref:`netvconnection-implementers-guide`). What no consumer does is move
bytes past the ``do_io_`` line.

That independence holds only as far as an implementation's fidelity to the
contract: it may change how bytes move, but not which events fire, in what
order, or with what VIO and buffer state (INV-C1). Swapping one
implementation for another must be invisible above the ``do_io_`` line.

The VIO: operations, disabling, resumption
==========================================

The identifiers this page leans on are the VIO's members; trimmed from
:ts:git:`include/iocore/eventsystem/VIO.h`:

.. code-block:: cpp

   class VIO
   {
   public:
     int64_t
     ntodo() const
     {
       return nbytes - ndone;
     }

     void reenable();
     void reenable_re();

     enum {
       NONE = 0,
       READ,
       WRITE,
     };

     Continuation     *cont      = nullptr;   // continuation receiving the events
     int64_t           nbytes    = 0;         // bytes the operation must complete
     int64_t           ndone     = 0;         // bytes already completed
     int               op        = VIO::NONE; // READ or WRITE
     MIOBufferAccessor buffer;                // reader or writer for the operation
     VConnection      *vc_server = nullptr;   // backpointer for the reenables
     Ptr<ProxyMutex>   mutex;                 // the consumer's mutex
   };

A ``do_io_read`` or ``do_io_write`` call installs an operation that remains
in effect: it is not consumed by a single transfer but covers arbitrarily
many transfers, buffer fills, and progress deliveries. Installing an
operation resets ``ndone`` to zero, records ``vio.cont`` and its mutex, and
starts the direction: ``do_io_read`` reenables when a buffer is supplied,
and on a null buffer detaches the buffer view (buffer blocks are refcounted
views over immutable committed bytes; `Buffers`_) and disables the read;
``do_io_write`` reenables when a reader and a nonzero ``nbytes`` are
supplied, and on a null reader only disables. ``nbytes = INT64_MAX`` means
stream until the source ends; the consumer may also resize ``nbytes``
mid-flight, typically once it learns a content length, while holding the
VIO's mutex, which it already does inside its own handler.

An implementation accounts ``ndone`` at the seam where bytes actually move,
in exactly one place per direction. On a read, ``ndone`` advances when
bytes enter the operation's buffer; on a write, it advances when the
underlying stream accepts bytes, and the bytes are consumed from the
operation's reader only then. Both actors read the VIO under the same
mutex, so split or duplicated accounting shows up as a transfer that ends
early, late, or never.

An operation that can make no forward progress disables itself: a read when
its buffer is full or the operation is complete, a write when its buffer is
empty, or either when the consumer disables it. Disabling means the
operation stops consuming turns. ``reenable`` is the peer announcing that
conditions changed: the consumer drained the read buffer, or refilled the
write buffer. It is not a command to perform I/O this instant, and it never
re-delivers buffered data (INV-R2); it marks the direction enabled and lets
the scheduler give the VC a turn when there is also progress to consume. If
progress is still impossible, a reenable is ignored and no events are
generated.

``reenable_re`` is the recursive variant. When the caller already holds the
lock of the scheduler the VC runs under, the normal case for a consumer
inside a delivery on the VC's thread, it runs the I/O synchronously on the
caller's stack when the direction has progress to consume, and otherwise
only marks it enabled; events may therefore be delivered before it returns,
to a consumer that is already inside a handler. Any other caller gets
plain ``reenable`` behavior. It saves a scheduling hop in a few hot paths
and in exchange imports every hazard in `Reentrancy`_ into the caller. An
implementation should prefer plain ``reenable``; for one that does supply
``reenable_re``, falling back to ``reenable`` semantics is always correct,
and the base class does exactly that.

A VC that is both consumer and producer (a layered transport transforming
an inner stream, or any transform) must resume itself. Its upstream signals
only for new external bytes (INV-R2) and its downstream reenables it only
when downstream space frees, so when room opens while undelivered input
sits buffered, nobody else will wake it: on each turn it moves as much
buffered input as capacity allows, and when it stops early it schedules its
own resumption (INV-R4).

The event vocabulary
====================

An event reports a fact about the transfer; the consumer's current handler
assigns its meaning (``SET_HANDLER`` re-binds meaning without changing what
flows), so an implementation never chooses an event based on what it
expects the consumer to do with it. The events below are the vocabulary,
and the firing condition stated with each one is the standard: an
implementation reproduces those conditions exactly, firing each event when
its condition holds and not otherwise.

Every event below is delivered to ``vio.cont`` with the VIO as the data
pointer, under the VIO's mutex, from the one thread the VC lives on (for a
net VC, its home ``ET_NET`` thread, described in
:ref:`netvconnection-implementers-guide`).

``VC_EVENT_READ_READY``
   Fires after a turn has moved new bytes into the operation's buffer and
   advanced ``ndone``, while the operation is incomplete
   (``vio.ntodo() > 0``). The required state at delivery is that the bytes
   are already in the buffer and ``ndone`` already counts them: the
   delivery announces a fact that is already true. The event is repeatable,
   but fires at most once per turn no matter how much the turn moved; a
   turn drains what the stream has to offer before it signals, so one
   delivery routinely announces several requests' worth of data.

   Two duties meet at this event, and each exists because of the other. The
   implementation's duty is exactly-once announcement: it announces a given
   byte once and never re-announces bytes the consumer has already been
   told about (INV-R2), so a fresh ``READ_READY`` means new bytes and
   nothing else. The consumer's duty follows from that: on each delivery it
   must consume every byte that allows it to make further progress, every
   complete unit in the buffer, however many arrived (INV-R1), because a
   complete unit left behind has already been announced and will never be
   announced again. The next event comes only when the far side produces
   new bytes; if the far side has gone quiet, or the buffer filled and the
   producer disabled itself, there is no next event, and the stranded unit
   waits until a timeout reaps the connection. The dependency runs the
   other way as well: exactly-once announcement is only workable because
   the consumer drains. An implementation that re-announced buffered data
   to relieve a lazy consumer would turn every partial unit into a busy
   loop, the consumer signalled over and over about bytes it cannot yet act
   on.

   The read side does not gate this event on the buffer's water mark; on
   the read side the water mark governs buffer growth (`Buffers`_).

``VC_EVENT_READ_COMPLETE``
   Fires when ``ndone`` reaches ``nbytes``, exactly once per operation. An
   implementation disables the read before delivering, so that whatever the
   consumer does mid-signal is interpreted against a finished operation. No
   further read events are delivered after it unless the consumer grows
   ``nbytes`` or issues a new ``do_io_read``.

``VC_EVENT_WRITE_READY``
   The write channel is demand-driven (INV-W1): this event is the VC asking
   its producer for more bytes, paced by the stream's ability to accept
   them. It is repeatable, and to a first approximation it fires while the
   operation is unfinished and the buffered bytes are not known to cover
   the remainder, provided the buffer stands at or below its water mark:
   the water mark is the level below which the VC asks for a top-up
   (`Buffers`_). The exact conditions are the socket implementation's two
   firing points, catalogued in :ref:`netvconnection-implementers-guide`;
   one of them, the post-drain ask in a turn that made no top-of-turn
   request, fires regardless of the water mark.

   The event obligates the consumer. On each ``WRITE_READY`` it must
   provide whatever bytes it can provide without waiting for further
   network events, or, if it can provide none, make sure that the wait it
   does enter ends in a ``reenable``. The VC does not ask twice for the
   same room: if the consumer leaves the buffer empty, the implementation
   disables the write, and nothing on the write side fires again merely
   because room remains, because room is a state, not an event. A consumer
   that returns empty-handed expecting to be asked again once the stream
   can accept more has deadlocked the transfer, and the deadlock ends at
   the inactivity timeout.

   The VC pulls on demand rather than letting the producer run ahead: an
   unpaced producer watches its writes complete at memory speed, the
   staging grows toward the size of the response, and end-to-end
   backpressure is severed.

``VC_EVENT_WRITE_COMPLETE``
   Fires when ``ndone`` reaches ``nbytes`` and every byte of the operation
   has been accepted by the underlying stream; for the socket VC, that is
   when the final ``sendmsg`` accepted them into the kernel. It fires
   exactly once per operation, and an implementation disables the write
   first. An implementation that stages bytes internally must deliver this
   only after the staging actually drains, scheduling the delivery off the
   producing stack if necessary (INV-W2): the canonical consumer response
   is ``do_io_close`` from inside the handler, and a premature completion
   lets that close truncate the tail.

``VC_EVENT_EOS``
   Fires when the stream reports end of stream on the read side. It is
   delivered in place of ``READ_READY``, with the read disabled first. The
   event states a fact, not a verdict: whether this end is normal or a
   truncation is decided by the consumer's current handler, which knows the
   protocol phase. End of stream is a persistent state, and an undelivered
   end of stream must survive the operation being disabled (INV-R5),
   however the implementation records it: a consumer that reenables later
   still receives it. An implementation that latches terminal state in a
   flag delivers the terminal event on the next enabled pass however late
   the consumer arrives, and it never suppresses a terminal signal to serve
   one consumer's scenario, because the suppression is itself a persistent
   state that outlives the scenario. How the socket VC preserves the fact
   without a flag, and what it does after the delivery, is in
   :ref:`netvconnection-implementers-guide`.

``VC_EVENT_ERROR``
   Fires when an operation against the underlying stream fails. An
   implementation stores the errno in the VC's ``lerrno`` before
   delivering; the event's data pointer is still the VIO, and the consumer
   reads the detail from the VC. Like ``EOS``, an error is a persistent
   state, and an implementation keeps it observable in one of two shapes:
   disable the direction and deliver once, or latch the error and keep
   delivering it while the direction stays enabled. It never uses a third
   shape in which the error is observed and then dropped. The socket VC
   uses both shapes on different paths
   (:ref:`netvconnection-implementers-guide`).

``VC_EVENT_INACTIVITY_TIMEOUT``, ``VC_EVENT_ACTIVE_TIMEOUT``
   Not fired by the byte-moving turns, and not part of the generic
   contract: a ``NetVConnection`` adds them, delivered on a schedule
   through its own machinery (:ref:`netvconnection-implementers-guide`).

The consumer may rely on the following ordering guarantees, and an
implementation must uphold them:

#. Events for a direction are delivered one at a time, from the VC's
   thread, under the VIO's mutex. There is no concurrent delivery to fend
   off; each delivery is one turn for the consumer.

#. ``READY`` events are repeatable; ``COMPLETE`` events fire exactly once
   per operation; ``EOS`` and ``ERROR`` end the direction's normal event
   stream. Completing and terminal deliveries disable the direction before
   they signal; the one stock exception is the socket VC's latched
   poll-error delivery, whose persistence depends on staying enabled.

#. Nothing is delivered after the consumer has called ``do_io_close``.
   ``do_io_read`` / ``do_io_write`` on a closed VC are errors and return
   ``nullptr``, with one exception: the all-null cancelling form is
   accepted, so a consumer can still detach its operation.

Buffers
=======

The buffer named in a ``do_io_`` call is a bounded channel between the two
actors (:ts:git:`include/iocore/eventsystem/IOBuffer.h`). Its blocks are
refcounted views over immutable committed bytes: readers walk their own
views, writers append only past ``end()`` of their own write block, and
committed bytes never change, so the VC and the consumer can drop their
views independently and the bytes outlive whichever goes first.

Two water-mark behaviors follow from the channel being bounded:

Growth gate (INV-B1)
   ``MIOBuffer::write_avail()`` appends a block only while the buffer is
   not above its water mark (``!high_water() && current_low_water()``),
   where ``high_water()`` measures unconsumed data to the slowest reader.
   With the default ``water_mark`` of zero, one unconsumed byte stops
   growth past the current block; a leaked or idle reader pins the
   measurement high and wedges growth permanently. The bound is the
   channel's capacity, and it is what keeps a fast producer from buffering
   an entire response, so an implementation must not code around it; a
   consumer that must accumulate more than a block before acting raises
   the water mark to the size of the unit it accumulates.

Refill threshold
   On the write side, ``high_water()`` gates ``WRITE_READY`` as described
   above: the water mark is the level below which the VC asks its producer
   to top up. Raising it asks earlier; zero asks only when empty.

Locking geometry
================

An implementation delivers events only while holding the consumer's mutex,
acquired with ``MUTEX_TRY_LOCK``; on failure, it requeues the delivery and
retries on a later turn (INV-C2). Delivery never blocks a thread;
contention defers a message. Blocking would stall every actor that shares
the thread, and it invites deadlock, since the lock's holder may be
waiting on something the VC provides.

The mutex that guards delivery is the consumer's. ``do_io_read`` and
``do_io_write`` copy ``c->mutex`` into ``vio.mutex``; the VIO keeps its own
reference (a ``Ptr<ProxyMutex>``) precisely so that the lock outlives its
owner: the mutex can still be taken safely even if the consumer has
already shut down and deallocated itself. The delivery helpers
additionally refuse to deliver when ``vio.mutex`` no longer equals
``vio.cont->mutex``: a consumer that re-targets a VIO must keep the two in
step, and the VC must not deliver under a stale lock.

The VC is an actor too, with a mutex of its own, given when it is created.
That mutex is the VC's mailbox lock: it serializes messages delivered to
the VC as a continuation, and it is not the lock delivery happens under.
An implementation must not confuse the two. (For a net VC, the timeout
sweep is the mailbox's principal sender, and the per-direction scheduling
state has locking regimes of its own;
:ref:`netvconnection-implementers-guide`.)

When the VC and its consumer share one mutex, the try-lock always succeeds
and every signal is a plain nested call. That is the common arrangement in
the HTTP path, and it is where implementation defects concentrate; the
consequences get their own section, `Reentrancy`_.

Reentrancy
==========

Delivery is synchronous. When the VC signals, ``vio.cont->handleEvent``
runs on the VC's stack, under the mutex it holds, and in the shared-mutex
arrangement that is the common case, nothing defers it. From inside that
call the consumer may ``reenable`` the VC, issue a new ``do_io_read`` or
``do_io_write``, resize the operation, or call ``do_io_close``, all before
the signal returns. Nested turns convert the mailbox from a queue into a
stack. This is the single largest source of implementer bugs, and the
following discipline is what makes it survivable.

Committing state before the signal
   The handler, flags, and VIO state must already describe the post-signal
   state when an implementation delivers: whatever arrives mid-signal is
   interpreted by the state in place. The reference implementation fills
   the buffer and advances ``ndone`` before ``READ_READY``, clears the
   enable before a completing or terminal event, and in ``do_io_close``
   sets its flags and only then marks ``closed``, behind a write barrier,
   so any observer that sees ``closed`` sees the finished state. An
   implementation prepares everything, performs one commit store, and then
   calls.

Signaling in tail position, or revalidating afterward
   The cheapest correct signal is the last thing a code path does. A path
   that must continue afterward can trust nothing it cached: it re-reads
   the VIO's ``ntodo``, the enable state, and the buffer's room, and it
   verifies that the lock still guards the right consumer, including
   whether ``vio.mutex`` changed because the consumer re-issued the
   operation to a different continuation. The return code must be honored:
   the delivery helpers return ``EVENT_DONE`` exactly when the VC was
   freed during the signal, and the only correct continuation is to unwind
   without touching another member. ``EVENT_DONE`` and ``EVENT_CONT`` are
   liveness reports about the object just signaled.

Counting live frames
   An implementation bumps a recursion counter around every delivery, as
   the reference implementation's delivery helpers do
   (:ref:`netvconnection-implementers-guide`). ``do_io_close`` is a
   request; reclamation is granted only at quiescence, meaning the
   outermost frame, recursion zero, and ``closed`` set. The counter is how
   the outermost frame knows it is outermost. Freeing anywhere else is the
   classic use-after-free: the frames below the handler still hold
   pointers into the object.

Keeping ``reenable`` and ``do_io_close`` safe at any moment
   Both may arrive from inside the VC's own signal. Neither may recurse
   into I/O: each sets state and schedules work. The reference
   ``reenable`` only marks the direction enabled and queues the VC for a
   later turn; the reference ``do_io_close`` only commits the closed state
   and defers the free (`Teardown`_). ``reenable_re`` is the deliberate
   exception, and callers accept its hazards.

An implementation routes events through one current handler and makes the
default arm assert: any event that has no meaning in the current state
fails the assertion. Dispatch is the state check; a misrouted or stale
event should fail an assertion at the state boundary, with the state's
name in the trace. For the same reason, a named handler function per phase
is preferable to one flag-driven handler: the handler name in a core dump
is what identifies the phase.

Teardown
========

``do_io_shutdown`` terminates one direction while the other continues: an
implementation shuts the underlying stream down for that direction,
disables it, drops the VIO's buffer views, clears its continuation, and
delivers no further events for that direction. The reference
implementation records the fact in shutdown flags that gate later
deliveries, including the timeout relays. This is how a proxy stops
reading from a client that has finished sending while still writing the
response.

``do_io_close`` is a release, not a destructor. After calling it the
consumer will never touch the VC or its VIOs again, and an implementation
must never signal that consumer again. It is also, canonically, called
from inside one of the VC's own deliveries (on ``WRITE_COMPLETE``, on
``EOS``, on a timeout), so the natural call site is the most dangerous
one, and an implementation must be safe there:

#. It commits the closed state: it disables both directions, clears the
   operations, then sets ``closed`` last, behind a write barrier, so any
   thread that observes ``closed`` observes a finished object.

#. It reclaims only at quiescence. The VC is freed inline only when no
   delivery is on the stack and the caller can detach the VC from its
   scheduler safely. Otherwise the ``closed`` flag remains as the request
   and a deferred reaper grants it: the outermost delivery helper frees as
   the recursion counter returns to zero (INV-L1), and the reference
   implementation's list walks and timeout sweep free any closed VC they
   encounter.

#. It withdraws every event source before reuse: everything that could
   still deliver into the VC is disconnected before the memory can be
   reissued. The reference reclamation order is walked in
   :ref:`netvconnection-implementers-guide`.

The general lifetime rule behind step 3 is that anything that can still
touch the object or its bytes (a queued event, a list membership, a kernel
registration, an operation still in flight) holds a reference, and freeing
is what happens when the holders are gone. Buffer memory already obeys it
by construction: blocks are refcounted views over immutable committed
bytes, so the VC and the consumer can drop their views independently and
the bytes outlive whichever goes first. Object memory must obey it by
discipline: a transport whose operations remain in flight after a turn
must cancel them and observe the cancellation on every free path before
the memory is reused (INV-L2); the recursion counter covers the frames on
the stack (INV-L1).

The laws
========

Reviews can cite these by number; the net-specific laws are in
:ref:`netvconnection-implementers-guide`.

#. Delivery never blocks: an implementation must take the consumer's mutex
   with a try-lock or requeue the delivery.

#. One delivery is one turn: an implementation must commit its state
   before any call that can signal it.

#. Events state facts; the receiver's current handler assigns meaning. An
   implementation must fire each event on its exact precondition, never on
   a prediction about the consumer.

#. An implementation must never announce buffered data twice; a reenable
   resumes the producer, it does not re-deliver.

#. An implementation must signal in tail position, or re-read the shared
   state afterward and honor the return code.

#. Close is a request; reclamation is granted only at quiescence:
   outermost frame, recursion zero, closed set.

#. Readers walk their views; writers append only past ``end()`` of their
   own write block; committed bytes never change.

#. Anything that can still touch the object or its bytes holds a
   reference; an implementation must free only when the holders are gone.

Pitfalls
========

+------------------------------+----------------------------------------------+
| Symptom                      | Where to look                                |
+==============================+==============================================+
| Use-after-free when a close  | Reclaimed before quiescence: freed inline    |
| arrives during the VC's own  | while the recursion counter was nonzero, or  |
| signal                       | a frame kept using members after a delivery  |
|                              | helper returned ``EVENT_DONE``.              |
+------------------------------+----------------------------------------------+
| Consumer never wakes;        | A water-mark growth gate wedged the buffer   |
| transfer stalls until a      | (INV-B1) and the producer stayed disabled    |
| timeout                      | forever; a stage stopped with buffered       |
|                              | input and no one scheduled to resume it      |
|                              | (INV-R4); or a consumer left the write       |
|                              | buffer empty on ``WRITE_READY``, waiting     |
|                              | for an ask that cannot come.                 |
+------------------------------+----------------------------------------------+
| Double ``READ_COMPLETE``, or | State not committed before signaling:        |
| events after ``EOS``         | ``enabled`` or ``ndone`` updated after the   |
|                              | delivery instead of before it.               |
+------------------------------+----------------------------------------------+
| Torn consumer state,         | Delivered without the consumer's mutex, or   |
| intermittent crashes         | under a stale ``vio.mutex`` after the        |
|                              | consumer re-issued the operation with a new  |
|                              | continuation.                                |
+------------------------------+----------------------------------------------+
| Stream corruption            | Wrote into committed bytes, or reused a      |
|                              | block that another holder still views        |
|                              | instead of appending past ``end()`` of its   |
|                              | own write block.                             |
+------------------------------+----------------------------------------------+
| ``ndone`` drift versus bytes | Fill/consume accounting split across paths;  |
| moved                        | advance ``ndone`` in one place per           |
|                              | direction, at the seam where bytes move.     |
+------------------------------+----------------------------------------------+
| Whole-thread stalls under    | Blocking work inside a turn: the thread      |
| load                         | hosts thousands of actors, and a held mutex  |
|                              | plus a blocked thread stalls them all.       |
+------------------------------+----------------------------------------------+

Further reading
===============

.. note::

   The design is a hand-compiled instance of ideas with a literature: the
   actor model of isolated state and message-passing (Agha, "Actors",
   1986); the compilation of actor programs onto threads and function
   calls (Plevyak, Zhang & Chien, POPL '95); and the reading of buffers as
   bounded channels between sequential processes (Kahn 1974; Hoare's CSP,
   1978).
