project(custom_allocator)
cmake_minimum_required(VERSION 3.18)
include(${CMAKE_CURRENT_SOURCE_DIR}/../../nabto_primary_files.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/../../nabto_modules_files.cmake)

find_package( Threads )

add_definitions(-DMBEDTLS_CONFIG_FILE=<custom_allocator_mbedtls_config.h>)

set(mbedtls_dir ${CMAKE_CURRENT_SOURCE_DIR}/../../3rdparty/mbedtls/mbedtls)
set(mbedtls_include_dir ${mbedtls_dir}/include)
set(mbedtls_src_dir ${mbedtls_dir}/library)

set(mbedtls_src
    ${mbedtls_src_dir}/aes.c
    ${mbedtls_src_dir}/aesni.c
    ${mbedtls_src_dir}/asn1parse.c
    ${mbedtls_src_dir}/asn1write.c
    ${mbedtls_src_dir}/base64.c
    ${mbedtls_src_dir}/bignum.c
    ${mbedtls_src_dir}/ccm.c
    ${mbedtls_src_dir}/cipher.c
    ${mbedtls_src_dir}/cipher_wrap.c
    ${mbedtls_src_dir}/ctr_drbg.c
    ${mbedtls_src_dir}/ecdh.c
    ${mbedtls_src_dir}/ecdsa.c
    ${mbedtls_src_dir}/ecp.c
    ${mbedtls_src_dir}/ecp_curves.c
    ${mbedtls_src_dir}/entropy.c
    ${mbedtls_src_dir}/entropy_poll.c
    ${mbedtls_src_dir}/error.c
    ${mbedtls_src_dir}/havege.c
    ${mbedtls_src_dir}/hmac_drbg.c
    ${mbedtls_src_dir}/md.c
    ${mbedtls_src_dir}/md_wrap.c
    ${mbedtls_src_dir}/oid.c
    ${mbedtls_src_dir}/pem.c
    ${mbedtls_src_dir}/pk.c
    ${mbedtls_src_dir}/pk_wrap.c
    ${mbedtls_src_dir}/pkparse.c
    ${mbedtls_src_dir}/pkwrite.c
    ${mbedtls_src_dir}/platform.c
    ${mbedtls_src_dir}/platform_util.c
    ${mbedtls_src_dir}/sha256.c
    ${mbedtls_src_dir}/certs.c
    ${mbedtls_src_dir}/x509.c
    ${mbedtls_src_dir}/x509_create.c
    ${mbedtls_src_dir}/x509_crt.c
    ${mbedtls_src_dir}/x509write_crt.c
    ${mbedtls_src_dir}/debug.c
    ${mbedtls_src_dir}/ssl_cache.c
    ${mbedtls_src_dir}/ssl_ciphersuites.c
    ${mbedtls_src_dir}/ssl_cli.c
    ${mbedtls_src_dir}/ssl_cookie.c
    ${mbedtls_src_dir}/ssl_srv.c
    ${mbedtls_src_dir}/ssl_ticket.c
    ${mbedtls_src_dir}/ssl_tls.c)

set(src
    ${ne_nn_src}
    ${ne_utils_src}
    ${ne_streaming_src}
    ${ne_coap_src}
    ${ne_mdns_src}
    ${ne_platform_src}
    ${ne_core_src}
    ${ne_api_src}
    ${ne_tinycbor_src}
    ${ne_mbedtls_module_src}
    ${ne_tcp_tunnels_src}
    ${ne_communication_buffer_src}
    ${ne_iam_src}
    ${mbedtls_src}
    ${ne_cjson_src}
    src/custom_allocator.c
    src/select_unix_platform.c
    ${ne_select_unix_src}
    ${ne_modules_threads_unix_src}
    ${ne_dns_src}
    ${ne_timestamp_src}
    ${ne_localip_src}
    ${ne_thread_event_queue_src}
    ${ne_event_queue_src}
    ${ne_modules_mdns_src}
    ${root_dir}/src/modules/threads/unix/nabto_device_threads_unix.c
    src/simple_coap_device.c
    ${root_dir}/apps/common/string_file.c
    ${root_dir}/3rdparty/tinyalloc/tinyalloc/tinyalloc.c
)

set(include_dirs
  ${root_dir}/src
  ${root_dir}/include
  ${root_dir}/nabto-common/components/coap/include
  ${root_dir}/nabto-common/components/streaming/include
  ${root_dir}/nabto-common/components/stun/include
  ${root_dir}/nabto-common/components/nn/include
  ${root_dir}/nabto-common/components/mdns/include
  ${root_dir}/3rdparty/tinycbor/extra
  ${root_dir}/3rdparty/tinycbor/tinycbor/src
  ${root_dir}/3rdparty/mbedtls/mbedtls/include
  ${root_dir}
  ${ne_cjson_include_dir}
  ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_config
)

add_executable(custom_allocator "${src}")

target_compile_definitions(custom_allocator PRIVATE -DHAVE_UNISTD_H)
target_include_directories(custom_allocator PRIVATE "${include_dirs}")
target_link_libraries( custom_allocator ${CMAKE_THREAD_LIBS_INIT} )
