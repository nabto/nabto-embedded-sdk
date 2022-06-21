find_library(WOLFSSL_LIBRARY wolfssl)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(wolfssl_random_src
  nm_wolfssl_random.c
  nm_wolfssl_util.c
  nm_wolfssl_cli.c
  nm_wolfssl_srv.c
  )


add_library( nm_wolfssl_random STATIC ${wolfssl_random_src})


target_link_libraries(nm_wolfssl_random  np_platform wolfssl m)
