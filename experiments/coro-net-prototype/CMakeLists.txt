# Standalone build + test matrix for the coroutine-net prototype. Intentionally
# independent of the main Traffic Server build — this is an exploratory spike.
#
# Build one configuration:
#   cmake -B build -DSANITIZER=none      # or asan / tsan
#   cmake --build build
#   ctest --test-dir build --output-on-failure
#
# Sweep the whole {sanitizer} x {backend} grid in one shot:
#   ./run-matrix.sh
cmake_minimum_required(VERSION 3.16)
project(coro_net_prototype CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Sanitizer selection (a build-level choice; asan and tsan cannot coexist).
# Each variant also defines how CTest should recognise a sanitizer failure:
#   - a regex that, if it appears in test output, fails the test
#   - the environment that makes the sanitizer abort (non-zero exit) on error
# ---------------------------------------------------------------------------
set(SANITIZER "none" CACHE STRING "Sanitizer build: none | asan | tsan")
set_property(CACHE SANITIZER PROPERTY STRINGS none asan tsan)

if(SANITIZER STREQUAL "asan")
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all -g -O1)
  add_link_options(-fsanitize=address,undefined)
  set(SAN_ENV "ASAN_OPTIONS=detect_leaks=1:abort_on_error=1;UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1")
  set(SAN_FAIL_RE "AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error|detected memory leaks")
elseif(SANITIZER STREQUAL "tsan")
  add_compile_options(-fsanitize=thread -g -O1)
  add_link_options(-fsanitize=thread)
  set(SAN_ENV "TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1")
  set(SAN_FAIL_RE "ThreadSanitizer")
elseif(SANITIZER STREQUAL "none")
  set(SAN_ENV "")
  set(SAN_FAIL_RE "")
else()
  message(FATAL_ERROR "Unknown SANITIZER='${SANITIZER}' (use none | asan | tsan)")
endif()
message(STATUS "coro-net: SANITIZER=${SANITIZER}")

find_package(Threads REQUIRED)

# Shared engine sources.
set(CORO_NET_LIB epoll_backend.cc uring_backend.cc coro_netvc.cc)

# coro_net    : single-threaded demo of seams 1-3 (echo + cancel-on-close).
# coro_net_mt : multi-threaded demo of seam 2 (per-thread backends, accept
#               hand-off, and cross-thread connection migration).
add_executable(coro_net main.cc ${CORO_NET_LIB})
add_executable(coro_net_mt mt_main.cc ${CORO_NET_LIB})
target_link_libraries(coro_net_mt PRIVATE Threads::Threads)

# ---------------------------------------------------------------------------
# Backends. epoll is always available; io_uring is added when liburing is found.
# BACKENDS drives the test matrix below, so io_uring tests appear automatically
# wherever liburing is present and are simply absent where it is not.
# ---------------------------------------------------------------------------
set(BACKENDS epoll)
find_path(LIBURING_INCLUDE_DIR liburing.h)
find_library(LIBURING_LIBRARY uring)
if(LIBURING_INCLUDE_DIR AND LIBURING_LIBRARY)
  list(APPEND BACKENDS uring)
  foreach(tgt coro_net coro_net_mt)
    target_compile_definitions(${tgt} PRIVATE HAVE_LIBURING)
    target_include_directories(${tgt} PRIVATE ${LIBURING_INCLUDE_DIR})
    target_link_libraries(${tgt} PRIVATE ${LIBURING_LIBRARY})
  endforeach()
  message(STATUS "coro-net: liburing found -> backends: ${BACKENDS}")
else()
  message(STATUS "coro-net: liburing NOT found -> backends: ${BACKENDS}")
endif()

# ---------------------------------------------------------------------------
# Test matrix machinery.
#
# Register an executable to run once per backend, with sanitizer-aware pass/fail
# detection. Adding a future test is a single line:
#
#     coro_add_matrix_test(<target> "<success-marker-regex>")
#
# The target must accept the backend name ("epoll" / "uring") as argv[1] and
# print the success marker on success. CTest then runs <target>.epoll and
# <target>.uring, each: passes only if the marker appears, fails if the active
# sanitizer prints a diagnostic, and carries labels backend=<be>;sanitizer=<san>
# so you can filter with `ctest -L backend=uring` etc.
# ---------------------------------------------------------------------------
enable_testing()

function(coro_add_matrix_test target marker)
  foreach(be IN LISTS BACKENDS)
    set(name "${target}.${be}")
    add_test(NAME ${name} COMMAND ${target} ${be})
    set_tests_properties(${name} PROPERTIES
      PASS_REGULAR_EXPRESSION "${marker}"
      LABELS "backend=${be};sanitizer=${SANITIZER}"
      TIMEOUT 60)
    if(SAN_FAIL_RE)
      set_tests_properties(${name} PROPERTIES FAIL_REGULAR_EXPRESSION "${SAN_FAIL_RE}")
    endif()
    if(SAN_ENV)
      set_tests_properties(${name} PROPERTIES ENVIRONMENT "${SAN_ENV}")
    endif()
  endforeach()
endfunction()

coro_add_matrix_test(coro_net    "done \\(3/3 checks passed\\)")
coro_add_matrix_test(coro_net_mt "clients 4/4, server VCs freed 4/4")
