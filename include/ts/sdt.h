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
#include "ink_autoconf.h"

#ifdef HAVE_SYSTEMTAP

#include <sys/sdt.h>

#define ATS_PROBE(subsystem, probe) DTRACE_PROBE(ats_##subsystem, probe)
#define ATS_PROBE1(subsystem, probe, param1) DTRACE_PROBE1(ats_##subsystem, probe, param1)
#define ATS_PROBE2(subsystem, probe, param1, param2) DTRACE_PROBE2(ats_##subsystem, probe, param1, param2)
#define ATS_PROBE3(subsystem, probe, param1, param2, param3) DTRACE_PROBE3(ats_##subsystem, probe, param1, param2, param3)
#define ATS_PROBE4(subsystem, probe, param1, param2, param3, param4) \
  DTRACE_PROBE4(ats_##subsystem, probe, param1, param2, param3, param4)
#define ATS_PROBE5(subsystem, probe, param1, param2, param3, param4, param5) \
  DTRACE_PROBE5(ats_##subsystem, probe, param1, param2, param3, param4, param5)
#define ATS_PROBE6(subsystem, probe, param1, param2, param3, param4, param5, param6) \
  DTRACE_PROBE6(ats_##subsystem, probe, param1, param2, param3, param4, param5, param6)
#define ATS_PROBE7(subsystem, probe, param1, param2, param3, param4, param5, param6, param7) \
  DTRACE_PROBE7(ats_##subsystem, probe, param1, param2, param3, param4, param5, param6, param7)
#define ATS_PROBE8(subsystem, probe, param1, param2, param3, param4, param5, param6, param7, param8) \
  DTRACE_PROBE8(ats_##subsystem, probe, param1, param2, param3, param4, param5, param6, param7, param8)
#define ATS_PROBE9(subsystem, probe, param1, param2, param3, param4, param5, param6, param7, param8, param9) \
  DTRACE_PROBE9(ats_##subsystem, probe, param1, param2, param3, param4, param5, param6, param7, param8, param9)
#define ATS_PROBE10(subsystem, probe, param1, param2, param3, param4, param5, param6, param7, param8, param9, param10) \
  DTRACE_PROBE10(ats_##subsystem, probe, param1, param2, param3, param4, param5, param6, param7, param8, param9, param10)
#define ATS_PROBE11(subsystem, probe, param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11) \
  DTRACE_PROBE11(ats_##subsystem, probe, param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11)
#define ATS_PROBE12(subsystem, probe, param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11,    \
                    param12)                                                                                                       \
  DTRACE_PROBE12(ats_##subsystem, probe, param1, param2, param3, param4, param5, param6, param7, param8, param9, param10, param11, \
                 param12)

#else

#define ATS_PROBE(...)
#define ATS_PROBE1(...)
#define ATS_PROBE2(...)
#define ATS_PROBE3(...)
#define ATS_PROBE4(...)
#define ATS_PROBE5(...)
#define ATS_PROBE6(...)
#define ATS_PROBE7(...)
#define ATS_PROBE8(...)
#define ATS_PROBE9(...)
#define ATS_PROBE10(...)
#define ATS_PROBE11(...)
#define ATS_PROBE12(...)

#endif
