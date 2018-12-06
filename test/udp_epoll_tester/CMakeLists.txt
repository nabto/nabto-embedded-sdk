cmake_minimum_required(VERSION 3.0)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(udp_epoll_tester_src
  ${src_dir}/main.c
  )

add_executable(udp_epoll_tester "${udp_epoll_tester_src}")

target_link_libraries(udp_epoll_tester
  np_platform
  nm_unix_logging
  nm_epoll
  nm_unix_communication_buffer
  nm_unix_timestamp
  nm_unix_dns
  )
