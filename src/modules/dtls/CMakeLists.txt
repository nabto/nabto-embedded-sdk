set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(dtls_src
  ${src_dir}/nm_dtls_cli.c
  )


add_library( nm_dtls_cli STATIC ${dtls_src})

target_link_libraries(nm_dtls_cli mbedtls)
