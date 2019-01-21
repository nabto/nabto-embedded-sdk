cmake_minimum_required(VERSION 3.0)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(dtls_server_tester_src
  ${src_dir}/main.c
  )

add_executable(dtls_server_tester "${dtls_server_tester_src}")

target_link_libraries(dtls_server_tester
  np_platform
  nm_logging
  nm_udp
  nm_unix_communication_buffer
  nm_timestamp
  nm_dtls_srv
  nc_core
  )
