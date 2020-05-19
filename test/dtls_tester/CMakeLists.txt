cmake_minimum_required(VERSION 3.0)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(dtls_tester_src
  ${src_dir}/main.c
  )

add_executable(dtls_tester "${dtls_tester_src}")

target_link_libraries(dtls_tester
  test_platform
  np_platform
  nm_logging_unix
  nm_unix_communication_buffer
  nm_timestamp
  nm_mbedtls_cli
  nc_core
  )
