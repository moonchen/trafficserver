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
#include <unordered_map>
#include <vector>
#include <shared_mutex>
#include "P_EventSystem.h"

// TODO: detect this with autotools
#define TS_USE_INOTIFY 1

#if TS_USE_INOTIFY
#include <sys/inotify.h>
#else
// implement this
#endif

using watch_handle_t = int;

// File watch info
struct file_info {
  std::filesystem::path path;
  Continuation *contp;
};

// A map of watched files under a directory:
//
//  filename:
//    watch_handle:
//      path
//      continuation
//    watch_handle:
//      path
//      conttinuation
//
// 1. A file can have multiple watch handles.
// 2. Different watch handles can have the same or different continuations.
// 3. Multiple files can be watched under one directory.
using DirectoryWatchMap = std::unordered_map<std::string, std::unordered_map<watch_handle_t, struct file_info>>;

// Directory watch info, for files that don't exist yet
struct dir_info {
  std::filesystem::path dname;
  DirectoryWatchMap files; // All of the watched files in this directory
};

struct watch_handle_info {
  int file_wd; // can be -1 or a real wd
  int dir_wd;  // can only be a real wd
};

constexpr int MAX_WATCHES = 10000;

class FileChangeManager
{
public:
  FileChangeManager()
  {
    for (int i = 0; i < MAX_WATCHES; i++) {
      free_handles.push_back(i);
    }
  }

  void init();

  /**
    Add a file watch

    @return a watch handle, or -1 on error
  */
  int add(const std::filesystem::path &path, Continuation *contp);

  /**
    Remove a file watch
  */
  void remove(int watch_handle);

private:
  std::thread poll_thread;

  int add_directory_watch(const std::filesystem::path &file_path, Continuation *contp);

  std::shared_mutex watch_handle_mutex;
  std::unordered_map<int, struct watch_handle_info> watch_handles;
  std::vector<int> free_handles;
#if TS_USE_INOTIFY
  std::shared_mutex file_watches_mutex;
  std::unordered_map<int, struct file_info> file_watches;
  std::shared_mutex dir_watches_mutex;
  std::unordered_map<int, struct dir_info> dir_watches;
  int inotify_fd;
#else
  // implement this
#endif
};

extern FileChangeManager fileChangeManager;
