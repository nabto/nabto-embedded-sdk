set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(dtls_cli_src
  ${src_dir}/nm_dtls_cli.c
  )

set(dtls_srv_src
  ${src_dir}/nm_dtls_srv.c
  )

add_library( nm_dtls_cli STATIC ${dtls_cli_src})
add_library( nm_dtls_srv STATIC ${dtls_srv_src})

target_link_libraries(nm_dtls_cli mbedtls)
target_link_libraries(nm_dtls_srv mbedtls)
