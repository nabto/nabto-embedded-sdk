cmake_minimum_required(VERSION 3.0)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(dtls_tester_src
  ${src_dir}/main.c
  )

add_executable(dtls_tester "${dtls_tester_src}")

target_link_libraries(dtls_tester
  np_platform
  nm_unix_logging
  nm_epoll
  nm_unix_communication_buffer
  nm_unix_timestamp
  nm_dtls
  nc_core
  )
