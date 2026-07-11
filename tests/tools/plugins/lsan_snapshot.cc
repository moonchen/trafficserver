/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Test-only plugin: on a lifecycle plugin message with tag "lsan_snapshot",
// run a *live* LeakSanitizer check (__lsan_do_recoverable_leak_check) while the
// server and its ownership roots are still live. This surfaces genuine orphans
// after a metric-gated quiescence point, which an at-SIGINT fast-exit check
// cannot distinguish from in-flight state. Only meaningful in an ASAN build.

#include <cstring>
#include <ts/ts.h>

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define LSAN_SNAPSHOT_HAVE_ASAN 1
#endif
#endif
#if !defined(LSAN_SNAPSHOT_HAVE_ASAN) && defined(__SANITIZE_ADDRESS__)
#define LSAN_SNAPSHOT_HAVE_ASAN 1
#endif

#if LSAN_SNAPSHOT_HAVE_ASAN
#include <sanitizer/lsan_interface.h>
#endif

static DbgCtl dbg_ctl{"lsan_snapshot"};

static constexpr const char MSG_TAG[] = "lsan_snapshot";

static int
lifecycle_handler(TSCont /* contp */, TSEvent event, void *edata)
{
  if (event != TS_EVENT_LIFECYCLE_MSG) {
    return 0;
  }
  auto *msg = static_cast<TSPluginMsg *>(edata);
  if (msg->tag == nullptr || std::strcmp(msg->tag, MSG_TAG) != 0) {
    return 0;
  }
#if LSAN_SNAPSHOT_HAVE_ASAN
  // Dbg (not TSError) so a clean snapshot does not trip the autest diags-error check.
  int const leaks = __lsan_do_recoverable_leak_check();
  Dbg(dbg_ctl, "live leak check ran: unsuppressed_leaks=%d", leaks);
#else
  Dbg(dbg_ctl, "built without ASAN; live leak check is a no-op");
#endif
  return 0;
}

void
TSPluginInit(int /* argc */, const char ** /* argv */)
{
  TSPluginRegistrationInfo info;
  info.plugin_name   = const_cast<char *>("lsan_snapshot");
  info.vendor_name   = const_cast<char *>("apache");
  info.support_email = const_cast<char *>("dev@trafficserver.apache.org");

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[lsan_snapshot] plugin registration failed");
    return;
  }
  TSLifecycleHookAdd(TS_LIFECYCLE_MSG_HOOK, TSContCreate(lifecycle_handler, nullptr));
}
