cmake_minimum_required(VERSION 3.0)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(attach_tester_src
  ${src_dir}/main.c
  )

add_executable(attach_tester "${attach_tester_src}")

target_link_libraries(attach_tester
  np_platform
  nm_unix_logging
  nm_epoll
  nm_unix_communication_buffer
  nm_unix_timestamp
  nm_dtls_cli
  nm_dtls_srv
  nc_core
  nm_unix_dns
  )
