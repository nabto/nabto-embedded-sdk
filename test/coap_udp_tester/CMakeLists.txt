cmake_minimum_required(VERSION 3.0)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(coap_udp_server_tester_src
  ${src_dir}/main.c
  )

set(coap_udp_client_tester_src
  ${src_dir}/client_main.c
  )

add_executable(coap_udp_server_tester "${coap_udp_server_tester_src}")
add_executable(coap_udp_client_tester "${coap_udp_client_tester_src}")

target_link_libraries(coap_udp_server_tester
  np_platform
  nm_logging
  nm_udp
  nm_unix_communication_buffer
  nm_timestamp
  )

target_link_libraries(coap_udp_client_tester
  np_platform
  nm_logging
  nm_udp
  nm_unix_communication_buffer
  nm_timestamp
  )
