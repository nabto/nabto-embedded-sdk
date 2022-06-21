find_library(WOLFSSL_LIBRARY wolfssl)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(wolfssl_common_src
  nm_wolfssl_timer.c
  nm_wolfssl_util.c
  )

set(wolfssl_cli_src
  ${wolfssl_common_src}
  nm_wolfssl_cli.c
  )

set(wolfssl_srv_src
  ${wolfssl_common_src}
  nm_wolfssl_srv.c
  )

set(wolfssl_random_src
  nm_wolfssl_random.c
  )


add_library( nm_wolfssl_cli STATIC ${wolfssl_cli_src})
add_library( nm_wolfssl_srv STATIC ${wolfssl_srv_src})
add_library( nm_wolfssl_random STATIC ${wolfssl_random_src})


target_link_libraries(nm_wolfssl_cli nn np_platform wolfssl m)
target_link_libraries(nm_wolfssl_srv np_platform wolfssl m)
target_link_libraries(nm_wolfssl_random  np_platform wolfssl m)
