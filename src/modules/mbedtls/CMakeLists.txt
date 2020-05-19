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


set(mbedtls_random_src
  nm_mbedtls_random.c
  )


add_library( nm_dtls_cli STATIC ${dtls_cli_src})
add_library( nm_dtls_srv STATIC ${dtls_srv_src})
add_library( nm_mbedtls_random STATIC ${mbedtls_random_src})


target_link_libraries(nm_dtls_cli 3rdparty_mbedtls nn np_platform)
target_link_libraries(nm_dtls_srv 3rdparty_mbedtls np_platform)
target_link_libraries(nm_mbedtls_random 3rdparty_mbedtls np_platform)
