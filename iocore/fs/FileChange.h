/** @file FileChange.h

  Watch for file system changes.

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
#include "tscore/ink_config.h"

#include <thread>
#include <chrono>
#include <filesystem>
#include <set>
#include <map>
#include <vector>
#include "P_EventSystem.h"

// TODO: detect this with autotools
#define TS_USE_INOTIFY 1

#if TS_USE_INOTIFY
#include <sys/inotify.h>
#else
// implement this
#endif

// File watch info
struct file_info {
  std::filesystem::path path;
  Continuation *contp;
};

// Directory watch info, for files that don't exist yet
struct dir_info {
  std::filesystem::path dname;
  std::map<const std::string, Continuation *> files;
};

class FileChangeManager
{
public:
  void init();
  int add(const std::filesystem::path &path, Continuation *contp);

private:
  std::thread poll_thread;

  int add_directory_watch(const std::filesystem::path &file_path, Continuation *contp);
#if TS_USE_INOTIFY
  std::map<int, struct file_info> file_watches;
  std::map<int, struct dir_info> dir_watches;
  int inotify_fd;
#else
  // implement this
#endif
};

extern FileChangeManager fileChangeManager;
