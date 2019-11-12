set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(dtls_server_tester_src
  ${src_dir}/main.c
  )

add_executable(dtls_server_tester "${dtls_server_tester_src}")

target_link_libraries(dtls_server_tester
  test_platform
  np_platform
  nm_logging_unix
  nm_unix_communication_buffer
  nm_timestamp
  nm_dtls_srv
  nc_core
  )
