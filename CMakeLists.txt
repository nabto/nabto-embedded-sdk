cmake_minimum_required(VERSION 3.0)
project(nabto-embedded-sdk)

# build all of nabto on linux, windows, mac

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR}/src)

include_directories(src/types/linux)
include_directories(src)

add_subdirectory(src/platform)
add_subdirectory(src/core)

add_definitions("-Wall")

set(test_runner_src
  ${CMAKE_CURRENT_SOURCE_DIR}/test/runner/linux.c
  )
add_subdirectory(src/modules/logging)
add_subdirectory(src/modules/timestamp)
add_subdirectory(src/modules/dns)
add_subdirectory(src/modules/communication_buffer)
add_subdirectory(src/modules/udp/epoll)
add_subdirectory(src/modules/crypto)
add_subdirectory(3rdparty/mbedtls)

add_subdirectory(test/udp_epoll_tester)
add_subdirectory(test/dtls_tester)
add_subdirectory(test/attach_test)

add_executable(unit_test "${test_runner_src}")

target_link_libraries(unit_test np_platform_test nc_core_test np_platform nc_core nm_unix_logging)
