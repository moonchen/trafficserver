# Standalone build for the coroutine-net prototype. Intentionally independent of
# the main Traffic Server build — this is an exploratory spike, not a component.
#
#   cmake -B build && cmake --build build && ./build/coro_net epoll
#                                            ./build/coro_net uring
cmake_minimum_required(VERSION 3.16)
project(coro_net_prototype CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(coro_net
  main.cc
  epoll_backend.cc
  uring_backend.cc
  coro_netvc.cc
)

# Use liburing if available so the io_uring backend is real; otherwise the
# prototype still builds and runs on the epoll backend.
find_path(LIBURING_INCLUDE_DIR liburing.h)
find_library(LIBURING_LIBRARY uring)
if(LIBURING_INCLUDE_DIR AND LIBURING_LIBRARY)
  message(STATUS "coro-net: liburing found, io_uring backend enabled")
  target_compile_definitions(coro_net PRIVATE HAVE_LIBURING)
  target_include_directories(coro_net PRIVATE ${LIBURING_INCLUDE_DIR})
  target_link_libraries(coro_net PRIVATE ${LIBURING_LIBRARY})
else()
  message(STATUS "coro-net: liburing NOT found, epoll backend only")
endif()
