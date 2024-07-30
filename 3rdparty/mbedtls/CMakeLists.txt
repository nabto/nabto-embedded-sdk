project(mbedtls)

# We create out own mbedtls library to only get the parts we need for dtls.

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library)

set(src_crypto
    ${src_dir}/aes.c
    ${src_dir}/aesni.c
    ${src_dir}/asn1parse.c
    ${src_dir}/asn1write.c
    ${src_dir}/base64.c
    ${src_dir}/bignum.c
    ${src_dir}/ccm.c
    ${src_dir}/cipher.c
    ${src_dir}/cipher_wrap.c
    ${src_dir}/ctr_drbg.c
    ${src_dir}/ecdh.c
    ${src_dir}/ecdsa.c
    ${src_dir}/ecp.c
    ${src_dir}/ecp_curves.c
    ${src_dir}/entropy.c
    ${src_dir}/entropy_poll.c
    ${src_dir}/error.c
    ${src_dir}/hmac_drbg.c
    ${src_dir}/md.c
    ${src_dir}/oid.c
    ${src_dir}/pem.c
    ${src_dir}/pk.c
    ${src_dir}/pk_wrap.c
    ${src_dir}/pkparse.c
    ${src_dir}/pkwrite.c
    ${src_dir}/platform.c
    ${src_dir}/platform_util.c
    ${src_dir}/sha256.c
    ${src_dir}/constant_time.c
    )


if (DEVICE_MBEDTLS_2)
set(src_x509
    ${src_dir}/x509.c
    ${src_dir}/x509_create.c
    ${src_dir}/x509_crt.c
    ${src_dir}/x509write_crt.c
)


set(src_tls
    ${src_dir}/debug.c
    ${src_dir}/ssl_cache.c
    ${src_dir}/ssl_ciphersuites.c
    ${src_dir}/ssl_cli.c
    ${src_dir}/ssl_cookie.c
    ${src_dir}/ssl_srv.c
    ${src_dir}/ssl_ticket.c
    ${src_dir}/ssl_tls.c
    ${src_dir}/ssl_msg.c
)
set(src_crypto
    ${src_dir}/aes.c
    ${src_dir}/aesni.c
    ${src_dir}/asn1parse.c
    ${src_dir}/asn1write.c
    ${src_dir}/base64.c
    ${src_dir}/bignum.c
    ${src_dir}/ccm.c
    ${src_dir}/cipher.c
    ${src_dir}/cipher_wrap.c
    ${src_dir}/ctr_drbg.c
    ${src_dir}/ecdh.c
    ${src_dir}/ecdsa.c
    ${src_dir}/ecp.c
    ${src_dir}/ecp_curves.c
    ${src_dir}/entropy.c
    ${src_dir}/entropy_poll.c
    ${src_dir}/error.c
    ${src_dir}/hmac_drbg.c
    ${src_dir}/md.c
    ${src_dir}/oid.c
    ${src_dir}/pem.c
    ${src_dir}/pk.c
    ${src_dir}/pk_wrap.c
    ${src_dir}/pkparse.c
    ${src_dir}/pkwrite.c
    ${src_dir}/platform.c
    ${src_dir}/platform_util.c
    ${src_dir}/sha256.c
    ${src_dir}/constant_time.c
    )

else()
set(src_x509
    ${src_dir}/x509.c
    ${src_dir}/x509_create.c
    ${src_dir}/x509_crt.c
    ${src_dir}/x509write.c
    ${src_dir}/x509write_crt.c
)

set(src_tls
    ${src_dir}/debug.c
    ${src_dir}/ssl_cache.c
    ${src_dir}/ssl_ciphersuites.c
    ${src_dir}/ssl_client.c
    ${src_dir}/ssl_cookie.c
    ${src_dir}/ssl_tls12_server.c
    ${src_dir}/ssl_tls12_client.c
    ${src_dir}/ssl_debug_helpers_generated.c
    ${src_dir}/ssl_ticket.c
    ${src_dir}/ssl_tls.c
    ${src_dir}/ssl_msg.c
)
set(src_crypto
    ${src_dir}/aes.c
    ${src_dir}/aesni.c
    ${src_dir}/asn1parse.c
    ${src_dir}/asn1write.c
    ${src_dir}/base64.c
    ${src_dir}/bignum.c
    ${src_dir}/bignum_core.c
    ${src_dir}/ccm.c
    ${src_dir}/cipher.c
    ${src_dir}/cipher_wrap.c
    ${src_dir}/ctr_drbg.c
    ${src_dir}/ecdh.c
    ${src_dir}/ecdsa.c
    ${src_dir}/ecp.c
    ${src_dir}/ecp_curves.c
    ${src_dir}/entropy.c
    ${src_dir}/entropy_poll.c
    ${src_dir}/error.c
    ${src_dir}/hmac_drbg.c
    ${src_dir}/md.c
    ${src_dir}/oid.c
    ${src_dir}/pem.c
    ${src_dir}/pk.c
    ${src_dir}/pk_wrap.c
    ${src_dir}/pkparse.c
    ${src_dir}/pkwrite.c
    ${src_dir}/platform.c
    ${src_dir}/platform_util.c
    ${src_dir}/sha256.c
    ${src_dir}/constant_time.c
    )


endif()

if (NABTO_DEVICE_MBEDTLS_PROVIDER MATCHES "module")

set(config_file config/nabto_mbedtls_config.h)

add_library(3rdparty_mbedtls "${src_tls}" "${src_x509}" "${src_crypto}" "${config_file}")

target_include_directories(3rdparty_mbedtls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/config)
target_include_directories(3rdparty_mbedtls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include)
if (DEVICE_MBEDTLS_2)
  target_compile_definitions(3rdparty_mbedtls PUBLIC -DMBEDTLS_CONFIG_FILE=<nabto_mbedtls_config.h>)
else()
  target_compile_definitions(3rdparty_mbedtls PUBLIC -DMBEDTLS_CONFIG_FILE=<nabto_mbedtls_config_v3.h>)
endif()

else()
  find_package(MbedTLS REQUIRED)
  add_library(3rdparty_mbedtls INTERFACE)
  target_link_libraries(3rdparty_mbedtls INTERFACE MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
endif()
