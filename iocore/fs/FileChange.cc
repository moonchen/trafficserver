/** @file FileChange.cc

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

#include "FileChange.h"
#include "tscore/Diags.h"

#include <cassert>
#include <functional>

// Globals
FileChangeManager fileChangeManager;
static constexpr auto TAG                = "FileChange";
static constexpr size_t INOTIFY_BUF_SIZE = 4096;

#if TS_USE_INOTIFY

static void
inotify_thread(int inotify_fd, std::map<int, struct file_info> &file_watches, std::map<int, struct dir_info> &dir_watches)
{
  for (;;) {
    char inotify_buf[INOTIFY_BUF_SIZE];

    // blocking read
    int rc = read(inotify_fd, inotify_buf, sizeof inotify_buf);

    if (rc == -1) {
      Error("Failed to read inotify: %s (%d)", strerror(errno), errno);
      if (errno == EINTR) {
        continue;
      } else {
        break;
      }
    }

    while (rc > 0) {
      struct inotify_event *event = reinterpret_cast<struct inotify_event *>(inotify_buf);

      // Process file events
      auto finfo_it = file_watches.find(event->wd);
      if (finfo_it != file_watches.end()) {
        const struct file_info &finfo = finfo_it->second;
        if (event->mask & (IN_CLOSE_WRITE | IN_ATTRIB)) {
          Debug(TAG, "Modify file event (%d) on %s", event->mask, finfo.path.c_str());
          // TODO: call contp
        } else if (event->mask & (IN_DELETE_SELF | IN_MOVED_FROM)) {
          Debug(TAG, "Delete file event (%d) on %s", event->mask, finfo.path.c_str());
          int rc2 = inotify_rm_watch(inotify_fd, event->wd);
          if (rc2 == -1) {
            Error("Failed to remove inotify watch on %s: %s (%d)", finfo.path.c_str(), strerror(errno), errno);
          }
          file_watches.erase(event->wd);
          // TODO: call contp
        }
      }

      // Process directory events
      auto dinfo_it = dir_watches.find(event->wd);
      if (dinfo_it != dir_watches.end()) {
        const struct dir_info &dinfo = dinfo_it->second;
        if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
          Debug(TAG, "Create file event (%d) on %s", event->mask, dinfo.dname.c_str());
          auto file_it = dinfo.files.find(event->name);
          if (file_it != dinfo.files.end()) {
            // This is a file we care about
            std::filesystem::path full_path{dinfo.dname};
            full_path /= event->name;
            int wd           = inotify_add_watch(inotify_fd, full_path.c_str(), IN_DELETE_SELF | IN_CLOSE_WRITE | IN_ATTRIB);
            file_watches[wd] = {full_path, file_it->second};
          }
          // TODO: call contp
        }
      }
    }
  }
}
#else
// Implement this
#endif

void
FileChangeManager::init()
{
#if TS_USE_INOTIFY
  // TODO: auto configure based on whether inotify is available
  inotify_fd = inotify_init1(IN_CLOEXEC);
  if (inotify_fd == -1) {
    Error("Failed to init inotify: %s (%d)", strerror(errno), errno);
    return;
  }

  poll_thread = std::thread(inotify_thread, inotify_fd, std::ref(file_watches), std::ref(dir_watches));
  poll_thread.detach();
#else
  // Implement this
  Warning("File change notification is not supported for this OS".);
#endif
}

// Add a watch for the file path's parent directory.
int
FileChangeManager::add_directory_watch(const std::filesystem::path &file_path, Continuation *contp)
{
  auto dname = file_path.parent_path();
  auto wd    = inotify_add_watch(inotify_fd, dname.c_str(), IN_CREATE | IN_MOVED_TO);
  return wd;
}

int
FileChangeManager::add(const std::filesystem::path &path, Continuation *contp)
{
#if TS_USE_INOTIFY
  // Let the OS handle multiple watches on one file.
  auto wd = inotify_add_watch(inotify_fd, path.c_str(), IN_DELETE_SELF | IN_CLOSE_WRITE | IN_ATTRIB);
  if (wd == -1) {
    Debug(TAG, "add(%s) resulted in %s (%d)", path.c_str(), strerror(errno), errno);
    if (errno == EACCES || errno == ENOENT) {
      return add_directory_watch(path, contp);
    } else {
      return wd;
    }
  } else {
    file_watches[wd] = {path, contp};
    return wd;
  }
#else
  // Implement this
#endif
}
