set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(dtls_src
  ${src_dir}/nm_dtls.c
  )


add_library( nm_dtls STATIC ${dtls_src})

target_link_libraries(nm_dtls mbedtls)
