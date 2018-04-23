cmake_minimum_required(VERSION 3.0)
project(nabto-embedded-sdk)

# build all of nabto on linux, windows, mac

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR}/src)

include_directories(src/types/linux)
include_directories(src)

add_subdirectory(src/platform)

set(test_runner_src
  ${CMAKE_CURRENT_SOURCE_DIR}/test/runner/linux.c
  ${CMAKE_CURRENT_SOURCE_DIR}/src/modules/logging/nabto_unix_logging.c
  )

add_executable(unit_test "${test_runner_src}")

target_link_libraries(unit_test nabto_platform_test nabto_platform)
