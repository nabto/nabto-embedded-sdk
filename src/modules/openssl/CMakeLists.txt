find_package(OpenSSL 3.5 REQUIRED)
find_package(NabtoCommon COMPONENTS nn)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(openssl_spake2_src
    nm_openssl_spake2.c
)

set(openssl_common_src
  nm_openssl_util.c
  )

set(openssl_cli_src
  nm_openssl_cli.c
  )

set(openssl_random_src
  nm_openssl_random.c
  )

set(openssl_srv_src
  nm_openssl_srv.c
)

# Fail the build if deprecated OpenSSL APIs are used.
set(openssl_api_definitions OPENSSL_API_COMPAT=30500 OPENSSL_NO_DEPRECATED)

add_library(nm_openssl_common STATIC ${openssl_common_src})
target_link_libraries(nm_openssl_common NabtoCommon::nn np_platform OpenSSL::SSL OpenSSL::Crypto)

add_library( nm_openssl_srv STATIC ${openssl_srv_src})
add_library( nm_openssl_cli STATIC ${openssl_cli_src})
add_library( nm_openssl_random STATIC ${openssl_random_src})
add_library( nm_openssl_spake2 STATIC ${openssl_spake2_src})

target_link_libraries(nm_openssl_srv NabtoCommon::nn np_platform nm_openssl_common OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(nm_openssl_cli NabtoCommon::nn np_platform nm_openssl_common OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(nm_openssl_random np_platform OpenSSL::Crypto)
target_link_libraries(nm_openssl_spake2 np_platform nm_openssl_common OpenSSL::Crypto)

foreach(t nm_openssl_common nm_openssl_srv nm_openssl_cli nm_openssl_random nm_openssl_spake2)
  target_compile_definitions(${t} PRIVATE ${openssl_api_definitions})
endforeach()
