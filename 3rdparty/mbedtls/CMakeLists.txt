project(mbedtls)

# We create out own mbedtls library to only get the parts we need for dtls.

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/library)

set(src_crypto
    ${src_dir}/aes.c
    ${src_dir}/aesni.c
    ${src_dir}/arc4.c
    ${src_dir}/asn1parse.c
    ${src_dir}/asn1write.c
    ${src_dir}/base64.c
    ${src_dir}/bignum.c
    ${src_dir}/blowfish.c
    ${src_dir}/camellia.c
    ${src_dir}/ccm.c
    ${src_dir}/cipher.c
    ${src_dir}/cipher_wrap.c
    ${src_dir}/cmac.c
    ${src_dir}/ctr_drbg.c
    ${src_dir}/des.c
    ${src_dir}/dhm.c
    ${src_dir}/ecdh.c
    ${src_dir}/ecdsa.c
    ${src_dir}/ecjpake.c
    ${src_dir}/ecp.c
    ${src_dir}/ecp_curves.c
    ${src_dir}/entropy.c
    ${src_dir}/entropy_poll.c
    ${src_dir}/error.c
    ${src_dir}/gcm.c
    ${src_dir}/havege.c
    ${src_dir}/hmac_drbg.c
    ${src_dir}/md.c
    ${src_dir}/md2.c
    ${src_dir}/md4.c
    ${src_dir}/md5.c
    ${src_dir}/md_wrap.c
    ${src_dir}/memory_buffer_alloc.c
    ${src_dir}/oid.c
    ${src_dir}/padlock.c
    ${src_dir}/pem.c
    ${src_dir}/pk.c
    ${src_dir}/pk_wrap.c
    ${src_dir}/pkcs12.c
    ${src_dir}/pkcs5.c
    ${src_dir}/pkparse.c
    ${src_dir}/pkwrite.c
    ${src_dir}/platform.c
    ${src_dir}/ripemd160.c
    ${src_dir}/rsa.c
    ${src_dir}/rsa_internal.c
    ${src_dir}/sha1.c
    ${src_dir}/sha256.c
    ${src_dir}/sha512.c
    ${src_dir}/threading.c
    ${src_dir}/timing.c
    ${src_dir}/version.c
    ${src_dir}/version_features.c
    ${src_dir}/xtea.c
)

set(src_x509
    ${src_dir}/certs.c
    ${src_dir}/pkcs11.c
    ${src_dir}/x509.c
    ${src_dir}/x509_create.c
    ${src_dir}/x509_crl.c
    ${src_dir}/x509_crt.c
    ${src_dir}/x509_csr.c
    ${src_dir}/x509write_crt.c
    ${src_dir}/x509write_csr.c
)

set(src_tls
    ${src_dir}/debug.c
    ${src_dir}/net_sockets.c
    ${src_dir}/ssl_cache.c
    ${src_dir}/ssl_ciphersuites.c
    ${src_dir}/ssl_cli.c
    ${src_dir}/ssl_cookie.c
    ${src_dir}/ssl_srv.c
    ${src_dir}/ssl_ticket.c
    ${src_dir}/ssl_tls.c
)

add_library(mbedtls "${src_tls}" "${src_x509}" "${src_crypto}")

target_include_directories(mbedtls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/config)
target_include_directories(mbedtls PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include)
