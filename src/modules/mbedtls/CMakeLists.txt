set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(mbedtls_spake2_src
    nm_mbedtls_spake2.c
)

set(dtls_common_src
  nm_mbedtls_timer.c
  nm_mbedtls_util.c
  )

set(dtls_cli_src
  ${dtls_common_src}
  nm_mbedtls_cli.c
  )

set(mbedtls_random_src
  nm_mbedtls_random.c
  )


set(dtls_srv_src
  ${dtls_common_src}
  nm_mbedtls_srv.c
)

add_library( nm_mbedtls_srv STATIC ${dtls_srv_src})
target_link_libraries(nm_mbedtls_srv 3rdparty_mbedtls nn np_platform)

add_library( nm_mbedtls_cli STATIC ${dtls_cli_src})
add_library( nm_mbedtls_random STATIC ${mbedtls_random_src})
add_library( nm_mbedtls_spake2 STATIC ${mbedtls_spake2_src})


target_link_libraries(nm_mbedtls_cli 3rdparty_mbedtls nn np_platform)
target_link_libraries(nm_mbedtls_random 3rdparty_mbedtls np_platform)
target_link_libraries(nm_mbedtls_spake2 3rdparty_mbedtls np_platform)
