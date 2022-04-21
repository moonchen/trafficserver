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
FileChangeManager::process_dir_event(struct inotify_event *event)
{
  std::shared_lock dir_watches_read_lock(dir_watches_mutex);
  auto dinfo_it = dir_watches.find(event->wd);
  if (dinfo_it != dir_watches.end()) {
    const struct dir_info &dinfo = dinfo_it->second;
    if (event->mask & (IN_CREATE | IN_MOVED_TO | IN_ATTRIB)) {
      Debug(TAG, "Create file event (%d) on %s", event->mask, dinfo.dname.c_str());
      auto file_it = dinfo.files.find(event->name);
      if (file_it != dinfo.files.end()) {
        // This is a file we care about
        std::filesystem::path full_path{dinfo.dname};
        full_path /= event->name;
        for (auto &[watch_handle, finfo] : file_it->second) {
          int wd = inotify_add_watch(inotify_fd, full_path.c_str(), IN_DELETE_SELF | IN_CLOSE_WRITE);
          if (wd == -1) {
            Error("Failed to add inotify watch on %s: %s (%d)", full_path.c_str(), strerror(errno), errno);
          } else {
            std::unique_lock watch_handles_write_lock(watch_handles_mutex);
            watch_handles[watch_handle].file_wd = wd;
            std::unique_lock file_watches_write_lock(file_watches_mutex);
            file_watches[wd] = finfo;
          }
          eventProcessor.schedule_imm(finfo.contp, ET_TASK);
        }
      }
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
  auto inotify_thread =
    [manager = this]() mutable {
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

          // Process directory events
          manager->process_dir_event(event);
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

// Add a watch for the file path's parent directory.
int
FileChangeManager::add_directory_watch(const std::filesystem::path &file_path, Continuation *contp)
{
#if TS_USE_INOTIFY
  auto dname = file_path.parent_path();
  {
    std::shared_lock dir_watches_read_lock(dir_watches_mutex);
    for (const auto &[wd, dinfo] : dir_watches) {
      if (dinfo.dname == dname) {
        return wd;
      }
    }
  }
  auto new_wd = inotify_add_watch(inotify_fd, dname.c_str(), IN_CREATE | IN_MOVED_TO);
  if (new_wd == -1) {
    Error("Failed to add directory watch to %s: %s, (%d)", file_path.c_str(), strerror(errno), errno);
  }

  std::unique_lock dir_watches_write_lock(dir_watches_mutex);
  dir_watches[new_wd] = {dname, {{file_path.filename(), {{new_wd, {file_path, contp}}}}}};
  return new_wd;
#else
  // Implement this
#endif
}

int
FileChangeManager::add(const std::filesystem::path &path, Continuation *contp)
{
  Debug(TAG, "Adding a watch on %s", path.c_str());
  std::lock_guard free_handles_lock(free_handles_mutex);
  if (free_handles.empty()) {
    Error("Maximum number of file watches reached.");
    return -1;
  }

#if TS_USE_INOTIFY
  auto dir_wd = add_directory_watch(path, contp);
  if (dir_wd == -1) {
    return -1;
  }
  // Let the OS handle multiple watches on one file.
  auto wd = inotify_add_watch(inotify_fd, path.c_str(), IN_DELETE_SELF | IN_CLOSE_WRITE | IN_ATTRIB);
  if (wd == -1) {
    Debug(TAG, "add(%s) resulted in %s (%d)", path.c_str(), strerror(errno), errno);
    if (errno == EACCES || errno == ENOENT) {
      // This is fine.  We added a watch to the parent directory in case this file gets created later.
    } else {
      Error("Failed to add file watch on %s: %s (%d)", path.c_str(), strerror(errno), errno);
      inotify_rm_watch(inotify_fd, dir_wd);
      return -1;
    }
  } else {
    std::unique_lock file_watches_write_lock(file_watches_mutex);
    file_watches[wd] = {path, contp};
  }

  auto new_handle = free_handles.back();
  free_handles.pop_back();
  std::unique_lock watch_handles_write_lock(watch_handles_mutex);
  watch_handles[new_handle] = {.file_wd = wd, .dir_wd = dir_wd};
  return new_handle;
#else
  // Implement this
#endif
}

void
FileChangeManager::remove(int watch_handle)
{
  Debug(TAG, "Removing watch handle %d", watch_handle);
  std::shared_lock watch_handles_read_lock(watch_handles_mutex);
  if (watch_handles.find(watch_handle) == watch_handles.end()) {
    Debug(TAG, "Tried to remove non-existant watch handle: %d", watch_handle);
    return;
  }

  const auto &whinfo = watch_handles[watch_handle];

  {
    std::unique_lock file_watches_write_lock(file_watches_mutex);
    assert(file_watches.find(whinfo.file_wd) != file_watches.end());
    if (whinfo.file_wd != -1) {
      if (inotify_rm_watch(inotify_fd, whinfo.file_wd) == -1) {
        Error("Failed to remove watch on %s: %s (%d)", file_watches[whinfo.file_wd].path.c_str(), strerror(errno), errno);
      }
    }
    file_watches.erase(whinfo.file_wd);
  }

  std::shared_lock dir_watches_read_lock(dir_watches_mutex);
  assert(dir_watches.find(whinfo.dir_wd) != dir_watches.end());
  auto &dir_info = dir_watches[whinfo.dir_wd];
  // Navigate the watches under this directory to find the correct one
  for (auto &[filename, finfos] : dir_info.files) {
    auto kv = finfos.find(watch_handle);
    if (kv != finfos.end()) {
      std::unique_lock dir_watches_write_lock(dir_watches_mutex);
      if (finfos.size() == 1) {
        // We are the last one to remove this dir watch
        if (inotify_rm_watch(inotify_fd, whinfo.dir_wd) == -1) {
          Error("Failed to remove directory watch on %s: %s (%d)", dir_info.dname.c_str(), strerror(errno), errno);
        }
        dir_watches.erase(whinfo.dir_wd);
      } else {
        assert(finfos.size() > 1);
        finfos.erase(watch_handle);
      }
    }
  }

  std::lock_guard watch_handles_write_lock(watch_handles_mutex);
  watch_handles.erase(watch_handle);
}