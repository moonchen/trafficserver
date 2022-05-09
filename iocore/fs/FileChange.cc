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
#include "P_EventSystem.h"

#include <cassert>
#include <functional>

// Globals
FileChangeManager fileChangeManager;
static constexpr auto TAG                = "FileChange";
static constexpr size_t INOTIFY_BUF_SIZE = 4096;

#if TS_USE_INOTIFY

void
FileChangeManager::process_file_event(struct inotify_event *event)
{
  std::shared_lock file_watches_read_lock(file_watches_mutex);
  auto finfo_it = file_watches.find(event->wd);
  if (finfo_it != file_watches.end()) {
    const struct file_info &finfo = finfo_it->second;
    if (event->mask & (IN_CLOSE_WRITE | IN_ATTRIB)) {
      Debug(TAG, "Modify file event (%d) on %s", event->mask, finfo.path.c_str());
      eventProcessor.schedule_imm(finfo.contp, ET_TASK);
    } else if (event->mask & (IN_DELETE_SELF | IN_MOVED_FROM)) {
      Debug(TAG, "Delete file event (%d) on %s", event->mask, finfo.path.c_str());
      int rc2 = inotify_rm_watch(inotify_fd, event->wd);
      if (rc2 == -1) {
        Error("Failed to remove inotify watch on %s: %s (%d)", finfo.path.c_str(), strerror(errno), errno);
      }
      eventProcessor.schedule_imm(finfo.contp, ET_TASK);
      std::unique_lock file_watches_write_lock(file_watches_mutex);
      file_watches.erase(event->wd);
    }
  }
}

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
  auto inotify_thread = [manager = this]() mutable {
    for (;;) {
      char inotify_buf[INOTIFY_BUF_SIZE];

      // blocking read
      int rc = read(manager->inotify_fd, inotify_buf, sizeof inotify_buf);

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
        manager->process_file_event(event);
      }
    }
  };
#else
// Implement this
#endif

  poll_thread = std::thread(inotify_thread);
  poll_thread.detach();
#else
// Implement this
Warning("File change notification is not supported for this OS".);
#endif
}

watch_handle_t
FileChangeManager::add(const std::filesystem::path &path, TSFileWatchKind kind, Continuation *contp)
{
  Debug(TAG, "Adding a watch on %s", path.c_str());
  watch_handle_t wd = 0;

#if TS_USE_INOTIFY
  // Let the OS handle multiple watches on one file.
  uint32_t mask = 0;
  if (kind == TS_WATCH_CREATE) {
    mask = IN_CREATE | IN_MOVED_TO;
  } else if (kind == TS_WATCH_DELETE) {
    mask = IN_DELETE_SELF | IN_MOVED_FROM;
  } else if (kind == TS_WATCH_MODIFY) {
    mask = IN_CLOSE_WRITE | IN_ATTRIB;
  }
  wd = inotify_add_watch(inotify_fd, path.c_str(), IN_DELETE_SELF | IN_CLOSE_WRITE | IN_ATTRIB);
  if (wd == -1) {
    Error("Failed to add file watch on %s: %s (%d)", path.c_str(), strerror(errno), errno);
    return -1;
  } else {
    std::unique_lock file_watches_write_lock(file_watches_mutex);
    file_watches[wd] = {path, contp};
  }

#endif
  Debug(TAG, "Watch handle = %d", wd);
  return wd;
}

void
FileChangeManager::remove(watch_handle_t watch_handle)
{
  Debug(TAG, "Deleting watch %d", watch_handle);
#if TS_USE_INOTIFY
  inotify_rm_watch(inotify_fd, watch_handle);
#endif
  std::unique_lock file_watches_write_lock(file_watches_mutex);
  file_watches.erase(watch_handle);
}