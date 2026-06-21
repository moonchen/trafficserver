#!/bin/bash
#
# SessionStart hook for Claude Code on the web.
#
# Installs the toolchain the coro-net prototype (experiments/coro-net-prototype)
# needs so that its lint + test matrix can run during a web session, then smoke-
# checks both. Runs in ASYNC mode: the session starts immediately while this work
# happens in the background. Idempotent and non-interactive.
#
# Trade-off of async: faster session startup, but there is a window at the very
# start where the toolchain may not be installed yet — if the first thing you do
# is build/test the prototype, wait for "deps installed" in the log below.
#
# Scope: this only sets up the coro-net prototype, not the full Traffic Server
# build (which has a much larger dependency set). Extend the apt list below if a
# session needs the whole tree built.
set -euo pipefail

# Web-only: locally you already have your own toolchain.
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

# Detach: let the agent loop start now; everything below runs in the background.
# asyncTimeout caps how long that background work may take (cold apt + build).
echo '{"async": true, "asyncTimeout": 300000}'

LOG="/tmp/coro-net-session-start.log"
: >"$LOG"
PROTO="${CLAUDE_PROJECT_DIR:-$(pwd)}/experiments/coro-net-prototype"

# --- 1. Dependencies (fatal on failure) -----------------------------------
{
  echo "== apt: installing build + lint deps =="
  export DEBIAN_FRONTEND=noninteractive
  APT="apt-get"
  command -v sudo >/dev/null 2>&1 && APT="sudo -n apt-get"
  $APT update -y
  # liburing-dev  -> real io_uring backend (epoll works without it)
  # cmake, g++, make -> build the prototype + drive CTest
  # clang-format  -> the repo lint gate
  $APT install -y --no-install-recommends liburing-dev cmake g++ make clang-format
} >>"$LOG" 2>&1

# --- 2. Smoke-check the lint gate (non-fatal) -----------------------------
lint="skipped"
if [ -d "$PROTO" ] && command -v clang-format >/dev/null 2>&1; then
  if (cd "$PROTO" && clang-format --dry-run --Werror ./*.h ./*.cc) >>"$LOG" 2>&1; then
    lint="passed"
  else
    lint="FAILED"
  fi
fi

# --- 3. Smoke-check the test matrix, epoll+uring under no sanitizer (non-fatal) ---
test="skipped"
if [ -d "$PROTO" ]; then
  if {
    cmake -S "$PROTO" -B "$PROTO/build-none" -DSANITIZER=none
    cmake --build "$PROTO/build-none" -j"$(nproc 2>/dev/null || echo 2)"
    ctest --test-dir "$PROTO/build-none" --output-on-failure
  } >>"$LOG" 2>&1; then
    test="passed"
  else
    test="FAILED"
  fi
fi

echo "coro-net prototype ready: deps installed, lint ${lint}, smoke tests ${test} (log: $LOG)"
