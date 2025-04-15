find_library(WOLFSSL_LIBRARY wolfssl)
find_package(NabtoCommon)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(wolfssl_spake2_src
    nm_wolfssl_spake2.c
)

set(wolfssl_common_src
  nm_wolfssl_util.c
  )

set(wolfssl_cli_src
  ${wolfssl_common_src}
  nm_wolfssl_cli.c
  )

set(wolfssl_random_src
  nm_wolfssl_random.c
  )

set(wolfssl_srv_src
  ${wolfssl_common_src}
  nm_wolfssl_srv.c
)

add_library( nm_wolfssl_srv STATIC ${wolfssl_srv_src})
target_link_libraries(nm_wolfssl_srv np_platform wolfssl m)

add_library( nm_wolfssl_cli STATIC ${wolfssl_cli_src})
add_library( nm_wolfssl_random STATIC ${wolfssl_random_src})
add_library( nm_wolfssl_spake2 STATIC ${wolfssl_spake2_src})


target_link_libraries(nm_wolfssl_cli NabtoCommon::nn np_platform wolfssl m)
target_link_libraries(nm_wolfssl_random np_platform wolfssl m)
target_link_libraries(nm_wolfssl_spake2 np_platform wolfssl m)
