# Standalone build for the coroutine-net prototype. Intentionally independent of
# the main Traffic Server build — this is an exploratory spike, not a component.
#
#   cmake -B build && cmake --build build && ./build/coro_net epoll
#                                            ./build/coro_net uring
cmake_minimum_required(VERSION 3.16)
project(coro_net_prototype CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

# Shared engine sources.
set(CORO_NET_LIB epoll_backend.cc uring_backend.cc coro_netvc.cc)

# coro_net    : single-threaded demo of seams 1-3 (echo + cancel-on-close).
# coro_net_mt : multi-threaded demo of seam 2 (per-thread backends, accept
#               hand-off, and cross-thread connection migration).
add_executable(coro_net main.cc ${CORO_NET_LIB})
add_executable(coro_net_mt mt_main.cc ${CORO_NET_LIB})
target_link_libraries(coro_net_mt PRIVATE Threads::Threads)

# Use liburing if available so the io_uring backend is real; otherwise the
# prototype still builds and runs on the epoll backend.
find_path(LIBURING_INCLUDE_DIR liburing.h)
find_library(LIBURING_LIBRARY uring)
foreach(tgt coro_net coro_net_mt)
  if(LIBURING_INCLUDE_DIR AND LIBURING_LIBRARY)
    target_compile_definitions(${tgt} PRIVATE HAVE_LIBURING)
    target_include_directories(${tgt} PRIVATE ${LIBURING_INCLUDE_DIR})
    target_link_libraries(${tgt} PRIVATE ${LIBURING_LIBRARY})
  endif()
endforeach()
if(LIBURING_INCLUDE_DIR AND LIBURING_LIBRARY)
  message(STATUS "coro-net: liburing found, io_uring backend enabled")
else()
  message(STATUS "coro-net: liburing NOT found, epoll backend only")
endif()
