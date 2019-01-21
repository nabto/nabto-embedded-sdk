cmake_minimum_required(VERSION 3.0)
project(nabto-embedded-sdk)

# build all of nabto on linux, windows, mac
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR}/src)

if ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
  include_directories(src/types/linux)
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
  include_directories(src/types/linux)
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  include_directories(src/types/linux)
endif()

include_directories(src)
include_directories(include)
include_directories(nabto-common-cpp/src)

add_subdirectory(src/platform)
add_subdirectory(src/core)
add_subdirectory(src/api)

add_definitions("-Wall")

set(test_runner_src
  ${CMAKE_CURRENT_SOURCE_DIR}/test/runner/linux.c
  )

add_subdirectory(src/modules/communication_buffer)
add_subdirectory(src/modules/dtls)
add_subdirectory(3rdparty/mbedtls)
add_subdirectory(nabto-common-cpp/src/streaming)
add_subdirectory(nabto-common-cpp/src/stun)
add_subdirectory(nabto-common-cpp/src/coap2)

if ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
  add_subdirectory(src/modules/dns)
  add_subdirectory(src/modules/udp/select_unix)
  add_subdirectory(src/modules/timestamp)
  add_subdirectory(src/modules/logging)
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
  add_definitions("/W1")
  add_subdirectory(src/modules/logging/win)
  add_subdirectory(src/modules/dns/win)
  add_subdirectory(src/modules/udp/select_win)
  add_subdirectory(src/modules/timestamp/win)
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  add_subdirectory(src/modules/dns)
  add_subdirectory(src/modules/logging)
  add_subdirectory(src/modules/timestamp)
  add_subdirectory(src/modules/udp/select_unix)
  add_subdirectory(src/modules/udp/epoll)
  add_subdirectory(test/dtls_tester)
  add_subdirectory(test/dtls_server_tester)
  add_subdirectory(test/attach_test)
  add_subdirectory(test/coap_udp_tester)
  add_subdirectory(test/low_lvl_api_tester)
endif()

add_subdirectory(test/api_test)
add_subdirectory(test/stream_echo)

if ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  add_executable(unit_test "${test_runner_src}")

target_link_libraries(unit_test
  np_platform_test
  nc_core_test
  np_platform
  nc_core
  nm_unix_logging)
endif()
