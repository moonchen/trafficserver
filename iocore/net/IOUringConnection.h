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

#include "I_SocketManager.h"
#include "I_NetProcessor.h"
#include "tscore/ink_platform.h"
#include "I_IO_URING.h"
#include "P_Connection.h"

#include <functional>
#include <utility>

class IOUringConnection;

class LambdaIOUringHandler : public IOUringCompletionHandler
{
public:
  LambdaIOUringHandler() {}
  LambdaIOUringHandler(std::function<void(int)> f) : _f(std::move(f)) {}
  void
  handle_complete(io_uring_cqe *cqe) override
  {
    auto res = cqe->res;
    _f(res);
  }

  std::string
  id() const override
  {
    return "lambda";
  }

private:
  std::function<void(int)> _f;
};

class IOUringConnection
{
public:
  SOCKET fd = NO_FD;         ///< Socket for connection.
  IpEndpoint addr;           ///< Associated address.
  socklen_t addrlen;         ///< size of addr
  bool is_bound     = false; ///< Flag for already bound to a local address.
  bool is_connected = false; ///< Flag for already connected.
  int sock_type     = 0;
  int ops_in_flight = 0; ///< The number of current active io_uring ops for this connection

  /** Create and initialize the socket for this connection.

      A socket is created and the options specified by @a opt are
      set. The socket is @b not connected.

      @note It is important to pass the same @a opt to this method and
      @c connect.

      handler is called with 0 on success, -errno on failure.

      @see connect
  */
  void open(
    NetVCOptions const &opt                 = DEFAULT_OPTIONS, ///< Socket options.
    const std::function<void(int)> &handler = [](int res) {}   ///< Callback handler.
  );

  /** Connect the socket.

      The socket is connected to the remote @a addr and @a port. The
      @a opt structure is used to control blocking on the socket. All
      other options are set via @c open. It is important to pass the
      same @a opt to this method as was passed to @c open.

      handler is called with 0 on success, -errno on failure.
      @see open
  */
  void connect(
    sockaddr const *to,                                        ///< Remote address and port.
    NetVCOptions const &opt                 = DEFAULT_OPTIONS, ///< Socket options
    const std::function<void(int)> &handler = [](int res) {}   ///< Callback handler.
  );

  /// Set the internal socket address struct.
  void
  setRemote(sockaddr const *remote_addr ///< Address and port.
  )
  {
    ats_ip_copy(&addr, remote_addr);
  }

  /** Close the socket.

      The socket is closed and the internal state is reset. The
      connection is no longer usable.

      @note This is an async call.  @a handler is called with 0 on success, -errno on failure.
  */
  void close(const std::function<void(int)> &handler = [](int res) {} ///< Callback handler.
  );

  void apply_options(const NetVCOptions &opt);

  virtual ~IOUringConnection();
  IOUringConnection() {}
  IOUringConnection(IOUringConnection const &that) = delete;

  /// Move
  IOUringConnection(Connection &&other)
  {
    is_connected = other.is_connected;
    is_bound     = other.is_bound;
    fd           = other.fd;
    other.fd     = NO_FD;
    addr         = other.addr;
    sock_type    = other.sock_type;
  }

  /// Default options.
  static NetVCOptions const DEFAULT_OPTIONS;

protected:
  LambdaIOUringHandler _open_handler;
  LambdaIOUringHandler _close_handler;
  LambdaIOUringHandler _connect_handler;
  void _cleanup();
  // SocketCompletionHandler _socket_handler;
};
