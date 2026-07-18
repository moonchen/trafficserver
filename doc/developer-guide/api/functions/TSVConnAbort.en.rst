.. Licensed to the Apache Software Foundation (ASF) under one or more
   contributor license agreements.  See the NOTICE file distributed
   with this work for additional information regarding copyright
   ownership.  The ASF licenses this file to you under the Apache
   License, Version 2.0 (the "License"); you may not use this file
   except in compliance with the License.  You may obtain a copy of
   the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   implied.  See the License for the specific language governing
   permissions and limitations under the License.

.. include:: ../../../common.defs

.. default-domain:: cpp

TSVConnAbort
************

Synopsis
========

.. code-block:: cpp

    #include <ts/ts.h>

.. function:: void TSVConnAbort(TSVConn connp, int error)

Description
===========

Close :arg:`connp` abnormally, releasing the vconnection without a normal
shutdown handshake. After this call the user will not be called back by the
vconnection again.

:func:`TSVConnAbort` must not be called on an inbound TLS connection while its
TLS handshake is in progress (for example from an SSL handshake hook); |TS|
rejects that with a fatal assertion. To fail a handshake from an SSL hook, call
:func:`TSVConnReenableEx` with ``TS_EVENT_ERROR``.
