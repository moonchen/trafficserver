-- Licensed to the Apache Software Foundation (ASF) under one or more
-- contributor license agreements.  See the NOTICE file distributed with this
-- work for additional information regarding copyright ownership.  The ASF
-- licenses this file to you under the Apache License, Version 2.0 (the
-- "License"); you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
-- License for the specific language governing permissions and limitations under
-- the License.

-- Round-robin GET across N distinct large cacheable objects. Hammering ONE
-- object serves it from the cache open-read / aggregation buffer and never
-- disk-reads, so the registered arena never engages; cycling distinct objects
-- closes each one's open-read with intervening reads, forcing an actual disk
-- read whose Doc buffer is drawn from the io_uring fixed-buffer arena and sent
-- with send_zc_fixed. (Each wrk thread has its own Lua state and counter, which
-- is fine -- every thread round-robins independently.)
local n = tonumber(os.getenv("ZC_RR_N")) or 16
local i = 0

wrk.headers["Host"] = "www.example.com"

request = function()
  local path = "/obj/" .. (i % n)
  i = i + 1
  return wrk.format("GET", path)
end
