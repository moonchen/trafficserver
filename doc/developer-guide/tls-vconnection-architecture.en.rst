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

.. _tls-vconnection-architecture:

TLS NetVConnection Architecture
*******************************

This document describes how :class:`SSLNetVConnection` provides a TLS-terminated
:class:`NetVConnection` to the rest of the proxy.

Overview
========

:class:`SSLNetVConnection` does not inherit from :class:`UnixNetVConnection`.
Instead it *holds* an inner :class:`UnixNetVConnection` (``_unvc``) that owns the
TCP socket, and drives the TLS state machine as an ordinary consumer of that
inner connection through the normal ``do_io_read`` / ``do_io_write`` / VIO event
plumbing. OpenSSL is connected to the transport by two in-memory BIOs backed by
``MIOBuffer`` objects::

    SSLNetVConnection : public NetVConnection
      _unvc                                  inner UnixNetVConnection (TCP)
      _read_buf,  _write_buf  : MIOBuffer    ciphertext to/from the socket
      BIO_s_miobuffer (x2)                   OpenSSL <-> MIOBuffer
      _user_read_vio,  _user_write_vio       plaintext VIOs handed to the user
      _transport_read_vio, _transport_write_vio   VIOs into _unvc

Plaintext that the user writes is encrypted by ``SSL_write`` into ``_write_buf``
and then sent to the socket by the inner connection. Ciphertext read from the
socket lands in ``_read_buf`` and is decrypted by ``SSL_read``.

Motivation
==========

In the previous design :class:`SSLNetVConnection` was a subclass of
:class:`UnixNetVConnection`, and the base (TCP) class contained TLS-specific
logic so the subclass could plug into it: an SSL handshake branch inside
``net_write_io``, a ``needs`` out-parameter on ``load_buffer_and_write`` to
report ``WANT_READ`` / ``WANT_WRITE`` back to the base class, and virtual hooks
(``sslStartHandShake``, ``getSSLHandShakeComplete``, ``readReschedule``, and
others) that existed only for the SSL subclass. The layered design removes that
coupling: the TCP class has no knowledge of TLS, and the TLS layer owns its
state machine entirely, reacting to VIO events from its inner connection.

The MIOBuffer BIOs
==================

``BIO_MIOBuffer`` (``src/iocore/net/BIO_MIOBuffer.{h,cc}``) is an OpenSSL ``BIO``
whose backing store is a ``MIOBuffer`` and/or an ``IOBufferReader``.
:class:`SSLNetVConnection` installs two of them on the ``SSL`` object with
``SSL_set_bio`` (which takes ownership):

* the read BIO reads ciphertext from ``_read_buf`` (an ``IOBufferReader``);
* the write BIO writes ciphertext into ``_write_buf``.

``miobuffer_set_buffer`` binds the writer and reader explicitly; either may be
null for a one-directional BIO.

A consequence worth noting: a ``MIOBuffer`` grows on demand, so the write BIO
always absorbs a full TLS record. ``SSL_write`` therefore never returns
``WANT_WRITE`` on this connection, and the code asserts that invariant rather
than carrying retry machinery for a case that cannot occur. Any future change
that binds a fixed-size or socket-backed write BIO would invalidate this.

Connection state
================

Two enums in ``P_SSLNetVConnection.h`` track the connection:

* ``SslState`` — ``HANDSHAKING``, ``HANDSHAKE_DONE``, ``SHUTDOWN_IN_PROGRESS``,
  ``TERMINATED``. ``TERMINATED`` means no further SSL I/O of any kind; the reason
  (clean close vs. error) is carried by ``lerrno``, not the state.
* ``TransportState`` — the state of the inner ``_unvc``: ``TRANSPORT_LIVE``,
  ``TRANSPORT_CLOSED``, ``TRANSPORT_ERROR``.

Event flow
==========

Inbound
-------

``SSLNextProtocolAccept::mainEvent`` allocates the :class:`SSLNetVConnection`,
copies the relevant state off the accepted :class:`UnixNetVConnection`, makes the
inner connection's action point at the SSL VC, and delivers ``NET_EVENT_ACCEPT``
with the inner connection as the event data.

``startEvent`` handles ``NET_EVENT_ACCEPT`` / ``NET_EVENT_OPEN``: it stores
``_unvc``, and issues ``do_io_read`` and ``do_io_write`` against the inner
connection to establish ``_transport_read_vio`` and ``_transport_write_vio``.
From then on ``mainEvent`` is the handler.

``mainEvent`` receives ``VC_EVENT_*`` from the inner connection and dispatches:

* read-ready -> ``_handle_transport_read_ready`` -> ``_trigger_ssl_read``: run
  ``SSL_read`` and deliver ``READ_READY`` / ``READ_COMPLETE`` / ``EOS`` /
  ``VC_EVENT_ERROR`` to the user;
* write-ready -> ``_handle_transport_write_ready``: continue the handshake, or
  encrypt pending plaintext (``_encrypt_data_for_transport``);
* EOS / error -> update ``TransportState``.

Events are delivered to the user's continuation through
``_signal_user(SignalSide, event)``.

Outbound
--------

``SSLNetProcessor::connect_re`` allocates the :class:`SSLNetVConnection`, makes
it the continuation of the inner connect, and delegates to
``unix_netProcessor.connect_re``. A successful TCP connect delivers
``NET_EVENT_OPEN`` to the SSL VC, which runs ``startEvent`` exactly as on the
inbound path. A TCP connect that fails *synchronously* delivers
``NET_EVENT_OPEN_FAILED`` (the event data is an ``errno``, not a connection).

The write path is demand-driven
===============================

When the user re-enables its write VIO, the TLS layer does **not** eagerly
encrypt the available plaintext. Encrypting ahead of the socket's ability to
send would grow ``_write_buf`` toward the size of the whole response and break
end-to-end backpressure (the user's write would "complete" at memory speed and
keep producing). Instead the layer re-arms the transport write and waits for a
transport ``WRITE_READY``, then encrypts in ``_handle_transport_write_ready``.
This keeps ``_write_buf`` small and lets backpressure propagate to the data
source. The amount of buffered ciphertext is bounded by
:ts:cv:`proxy.config.ssl.write_buffer_water_mark`.

Because the encrypted bytes may still be buffered when ``SSL_write`` returns,
``VC_EVENT_WRITE_COMPLETE`` is not delivered until ``_write_buf`` has actually
drained to the transport, and it is delivered out of line (scheduled, not from
the current stack). The consumer typically closes the connection from its
``WRITE_COMPLETE`` handler; signalling inline -- while the inner connection's
``net_write_io`` is still on the stack and still references ``_write_buf`` -- would
let that close truncate the response or free a buffer that is still in use.

The read path and terminal state
================================

``EOS`` and ``VC_EVENT_ERROR`` are persistent conditions: once the transport is
closed or errored, it will not signal again. The read BIO holds only ciphertext
and cannot itself surface a transport error. A consumer that re-enables its read
VIO after the transport has terminated therefore must still observe the
terminal event, so ``reenable`` schedules an out-of-line read drive when there
is buffered ciphertext to deliver or the transport has already terminated.

Object lifecycle
================

A user event handler may call ``do_io_close`` on the VC from within the callback
(for example, closing the connection on ``WRITE_COMPLETE``). ``_signal_user``
tracks its re-entrancy depth; if the VC is closed while a signal is still on the
stack, the actual free is deferred until the outermost ``_signal_user`` unwinds.
``do_io_close`` frees inline only when no signal is in progress.

Blind tunnels
=============

A pure blind tunnel (``SNIRoutingType::BLIND``, ``tunnel_route`` in
:file:`sni.yaml`) forwards raw bytes and never terminates TLS. When the SNI
selects a blind tunnel, the connection is handed to a dedicated
:class:`TunnelNetVConnection`
(``src/iocore/net/TunnelNetVConnection.cc``, ``P_TunnelNetVConnection.h``), which forwards bytes between
the client and the origin without an SSL object. ``FORWARD`` and
``PARTIAL_BLIND`` routes terminate TLS and tunnel the decrypted stream through
the HTTP state machine; those use :class:`SSLNetVConnection` normally.

OpenSSL and BoringSSL
=====================

The write/read BIO callbacks have two forms. Where ``BIO_meth_set_write_ex`` is
available (OpenSSL 1.1.1 and later) the ``_ex`` callbacks are used directly; on
BoringSSL the classic ``BIO_meth_set_write`` / ``BIO_meth_set_read`` callbacks
are registered and wrap the same ``_ex`` implementations. Both libraries are
supported, so changes to the BIO layer must compile and pass tests against both.

Asynchronous handshake
======================

When TLS handshake offload is enabled (for example, an async-capable engine or
provider), OpenSSL exposes a set of wait file descriptors. ``AsyncTLSEventIO``
(``include/iocore/net/AsyncTLSEventIO.h``,
``src/iocore/net/AsyncTLSEventIO.cc``) registers those descriptors with the
event system; when one becomes ready, ``handle_async_tls_ready`` resumes the
handshake drive.

Cross-thread reuse from the global session pool
===============================================

When :ts:cv:`proxy.config.http.server_session_sharing.pool` is ``global``, a
pooled TLS origin connection may be reused by an ``HttpSM`` running on a
different thread than the one the connection lives on.
:class:`SSLNetVConnection`'s ``migrateToCurrentThread`` migrates it: the inner
transport (the fd and its epoll registration) is moved with the generic
:class:`UnixNetVConnection` migration, while the ``SSL`` object and the two
``MIOBuffer`` BIOs it is wired to travel with the VC unchanged. The migration is
serialized by the pool mutex, which the acquiring thread holds across the
operation, so the connection's original thread cannot touch it concurrently.

HTTP/2 origin sessions are pooled per-thread (``Http2ServerSession`` uses the
thread pool), so they are always reused on their own thread and never take this
path.
