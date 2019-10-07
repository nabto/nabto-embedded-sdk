cmake_minimum_required(VERSION 3.0)
project(nabto-embedded-sdk)

include(CheckIncludeFiles)

# build all of nabto on linux, windows, mac
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_STANDARD 14)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR}/src)

if ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
  include_directories(src/types/linux)
  add_definitions("-Wall")
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
  set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out CACHE STRING "" )
  set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out CACHE STRING "" )
  include_directories(src/types/linux)
  add_definitions("/W4")
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  include_directories(src/types/linux)
  add_definitions("-Wall")
endif()

include_directories(src)
include_directories(include)
include_directories(nabto-common-cpp/src)

add_subdirectory(src/platform)
add_subdirectory(src/core)
add_subdirectory(src/api)

set(CMAKE_BUILD_TYPE Debug)

set(test_runner_src
  ${CMAKE_CURRENT_SOURCE_DIR}/test/runner/linux.c
  )

add_subdirectory(src/modules/communication_buffer)
add_subdirectory(src/modules/dtls)
add_subdirectory(3rdparty/mbedtls)
add_subdirectory(3rdparty/cjson)
add_subdirectory(3rdparty/gopt)
add_subdirectory(3rdparty/tinycbor)
add_subdirectory(3rdparty/nlohmann-json)
add_subdirectory(3rdparty/cxxopts)
add_subdirectory(nabto-common-cpp/src/streaming)
add_subdirectory(nabto-common-cpp/src/stun)
add_subdirectory(nabto-common-cpp/src/coap)
add_subdirectory(nabto-common-cpp/src/mdns)

add_subdirectory(src/modules/logging/api)
add_subdirectory(src/modules/mdns)
add_subdirectory(src/modules/tcptunnel)


CHECK_INCLUDE_FILES("sys/epoll.h" HAVE_EPOLL_HEADERS)

if (HAVE_EPOLL_HEADERS)
  add_subdirectory(src/modules/epoll)
endif()

if ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
  add_subdirectory(src/modules/dns/unix)
  add_subdirectory(src/modules/select_unix)
  add_subdirectory(src/modules/timestamp/unix)
  add_subdirectory(src/modules/logging/unix)
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
  add_subdirectory(src/modules/logging/win)
  add_subdirectory(src/modules/dns/win)
  add_subdirectory(src/modules/udp/select_win)
  add_subdirectory(src/modules/timestamp/win)
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  add_subdirectory(src/modules/logging/unix)
  add_subdirectory(src/modules/dns/unix)
  add_subdirectory(src/modules/timestamp/unix)
  add_subdirectory(src/modules/select_unix)
endif()

add_subdirectory(test)

add_subdirectory(examples/common)
add_subdirectory(examples/heat_pump)
add_subdirectory(examples/tcptunnel)
add_subdirectory(examples/stream_echo)

if ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  add_executable(unit_test "${test_runner_src}")

  target_link_libraries(unit_test
    np_platform_test
    nc_core_test
    np_platform
    nc_core
    nm_logging)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/test)
add_subdirectory(test_cpp)
