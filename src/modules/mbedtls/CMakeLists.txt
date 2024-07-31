find_package(MbedTLS REQUIRED COMPONENTS mbedtls mbedcrypto mbedx509)
find_package(NabtoCommon COMPONENTS nn)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(mbedtls_spake2_src
    nm_mbedtls_spake2.c
)

set(dtls_common_src
  nm_mbedtls_timer.c
  nm_mbedtls_util.c
  )

set(dtls_cli_src
  nm_mbedtls_cli.c
  )

set(mbedtls_random_src
  nm_mbedtls_random.c
  )


set(dtls_srv_src
  nm_mbedtls_srv.c
)

add_library(nm_mbedtls_common ${dtls_common_src})
target_link_libraries(nm_mbedtls_common NabtoCommon::nn MbedTLS::mbedcrypto)

add_library( nm_mbedtls_srv STATIC ${dtls_srv_src})
target_link_libraries(nm_mbedtls_srv MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509 NabtoCommon::nn np_platform nm_mbedtls_common)

add_library( nm_mbedtls_cli STATIC ${dtls_cli_src})
add_library( nm_mbedtls_random STATIC ${mbedtls_random_src})
add_library( nm_mbedtls_spake2 STATIC ${mbedtls_spake2_src})


target_link_libraries(nm_mbedtls_cli MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509 NabtoCommon::nn np_platform nm_mbedtls_common)
target_link_libraries(nm_mbedtls_random MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509 np_platform)
target_link_libraries(nm_mbedtls_spake2 MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509 np_platform)
