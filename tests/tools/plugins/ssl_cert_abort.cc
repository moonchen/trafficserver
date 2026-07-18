/** @file

  Test plugin: fail every TLS handshake from the SSL cert hook.

  Failing a handshake from an SSL hook is done with the reenable-based path,
  TSVConnReenableEx(vc, TS_EVENT_ERROR): the hook flags the error and ATS
  delivers the failure and tears the connection down on its own schedule,
  outside the OpenSSL frame the hook was invoked from. (Closing the VC directly
  from the hook -- TSVConnClose/TSVConnAbort -- is not a supported action and is
  rejected by the API.) This plugin exercises the supported fail path from
  TS_SSL_CERT_HOOK, which fires synchronously mid-SSL_accept.

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

#define PN  "ssl_cert_abort"
#define PCP "[" PN " Plugin] "

namespace
{
DbgCtl dbg_ctl{PN};

int
CB_Cert_Fail(TSCont /* cont ATS_UNUSED */, TSEvent /* event ATS_UNUSED */, void *edata)
{
  TSVConn ssl_vc = static_cast<TSVConn>(edata);
  Dbg(dbg_ctl, "cert hook: failing the handshake for ssl_vc=%p via TSVConnReenableEx(TS_EVENT_ERROR)", ssl_vc);
  TSVConnReenableEx(ssl_vc, TS_EVENT_ERROR);
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

  TSCont cb = TSContCreate(&CB_Cert_Fail, nullptr);
  TSHttpHookAdd(TS_SSL_CERT_HOOK, cb);
}
