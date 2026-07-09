/** @file

  Test plugin: abort a TLS handshake from within an SSL hook via TSVConnAbort.

  A plugin is allowed to fail a handshake from an SSL hook. The documented,
  reenable-based path (TSVConnReenableEx(vc, TS_EVENT_ERROR)) defers the actual
  teardown. TSVConnAbort(vc, error), by contrast, calls do_io_close(error)
  directly. This callback runs synchronously while ATS is still nested inside
  OpenSSL's SSL_accept() (the cert callback fires mid-ClientHello-processing), so
  a layered SSLNetVConnection that frees its SSL object inline here destroys it
  out from under the OpenSSL frame that is still on the stack -- a use-after-free
  inside libssl. This plugin exists to exercise exactly that path.

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

#include <ts/ts.h>
#include <cstdint>

#define PN  "ssl_cert_abort"
#define PCP "[" PN " Plugin] "

namespace
{
DbgCtl dbg_ctl{PN};

// Nonzero so do_io_close(error) takes the error (lerrno != -1) path -- the one
// that historically decided to free inline on a heuristic that did not account
// for being nested in an OpenSSL callback frame.
constexpr int ABORT_ERRNO = 1;

int
CB_Cert_Abort(TSCont /* cont ATS_UNUSED */, TSEvent /* event ATS_UNUSED */, void *edata)
{
  TSVConn ssl_vc = static_cast<TSVConn>(edata);
  Dbg(dbg_ctl, "cert hook: aborting ssl_vc=%p synchronously via TSVConnAbort", ssl_vc);
  TSVConnAbort(ssl_vc, ABORT_ERRNO);
  return TS_SUCCESS;
}
} // namespace

void
TSPluginInit(int /* argc ATS_UNUSED */, const char * /* argv ATS_UNUSED */[])
{
  TSPluginRegistrationInfo info;
  info.plugin_name   = const_cast<char *>(PN);
  info.vendor_name   = const_cast<char *>("apache");
  info.support_email = const_cast<char *>("dev@trafficserver.apache.org");
  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError(PCP "registration failed");
    return;
  }

  TSCont cb = TSContCreate(&CB_Cert_Abort, nullptr);
  TSHttpHookAdd(TS_SSL_CERT_HOOK, cb);
}
