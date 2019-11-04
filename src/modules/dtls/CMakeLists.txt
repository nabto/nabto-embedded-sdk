set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(dtls_common_src
  nm_dtls_timer.c
  )

set(dtls_cli_src
  ${dtls_common_src}
  ${src_dir}/nm_dtls_cli.c
  ${src_dir}/nm_dtls_util.c
  )

set(dtls_srv_src
  ${dtls_common_src}
  ${src_dir}/nm_dtls_srv.c
  ${src_dir}/nm_dtls_util.c
  )

set(dtls_test_src
  ${src_dir}/nm_dtls_test.c
  ${src_dir}/nm_dtls_util.c
  ${src_dir}/nm_dtls_srv.c
  ${src_dir}/nm_dtls_cli.c
  )

add_library( nm_dtls_cli STATIC ${dtls_cli_src})
add_library( nm_dtls_srv STATIC ${dtls_srv_src})

#add_executable( nm_dtls_test ${dtls_test_src})

target_link_libraries(nm_dtls_cli 3rdparty_mbedtls)
target_link_libraries(nm_dtls_srv 3rdparty_mbedtls)

#target_link_libraries(nm_dtls_test
#  np_platform
#  nm_unix_communication_buffer
#  nm_unix_timestamp
#  nc_core
#  mbedtls
#  )
