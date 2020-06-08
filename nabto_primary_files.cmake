set(root_dir ${CMAKE_CURRENT_LIST_DIR})

message("Using embedded dir:" ${root_dir})

set(ne_utils
  ${root_dir}/nabto-common/components/stun/src/nabto_stun_log.c
  ${root_dir}/nabto-common/components/stun/src/nabto_stun_client.c
  ${root_dir}/nabto-common/components/stun/src/nabto_stun_message.c
  ${root_dir}/nabto-common/components/nn/src/nn/llist.c
  ${root_dir}/nabto-common/components/nn/src/nn/vector.c
  ${root_dir}/nabto-common/components/nn/src/nn/string_set.c
  ${root_dir}/nabto-common/components/nn/src/nn/log.c
  ${root_dir}/nabto-common/components/nn/src/nn/string_map.c
)


set(ne_streaming
  ${root_dir}/nabto-common/components/streaming/src/nabto_stream_congestion_control.c
  ${root_dir}/nabto-common/components/streaming/src/nabto_stream_window.c
  ${root_dir}/nabto-common/components/streaming/src/nabto_stream_log_helper.c
  ${root_dir}/nabto-common/components/streaming/src/nabto_stream_log.c
  ${root_dir}/nabto-common/components/streaming/src/nabto_stream_util.c
  ${root_dir}/nabto-common/components/streaming/src/nabto_stream_packet.c
  ${root_dir}/nabto-common/components/streaming/src/nabto_stream.c
  ${root_dir}/nabto-common/components/streaming/src/nabto_stream_flow_control.c
  ${root_dir}/nabto-common/components/streaming/src/nabto_stream_memory.c
)

set(ne_mdns
#  ${root_dir}/nabto-common/components/mdns/src/mdns_server.c
)

set(ne_coap
  ${root_dir}/nabto-common/components/coap/src/nabto_coap.c
  ${root_dir}/nabto-common/components/coap/src/nabto_coap_client_impl.c
  ${root_dir}/nabto-common/components/coap/src/nabto_coap_server_impl_incoming.c
  ${root_dir}/nabto-common/components/coap/src/nabto_coap_server_impl.c
)

set(ne_platform
  ${root_dir}/src/platform/np_udp.c
  ${root_dir}/src/platform/np_event_queue.c
  ${root_dir}/src/platform/np_error_code.c
  ${root_dir}/src/platform/np_timestamp.c
  ${root_dir}/src/platform/np_completion_event.c
  ${root_dir}/src/platform/np_logging.c
  ${root_dir}/src/platform/np_util.c
  ${root_dir}/src/platform/np_ip_address.c
)

set(ne_core
  ${root_dir}/src/core/nc_client_connection.c
  ${root_dir}/src/core/nc_coap_packet_printer.c
  ${root_dir}/src/core/nc_attacher_attach_start.c
  ${root_dir}/src/core/nc_client_connection_dispatch.c
  ${root_dir}/src/core/nc_udp_dispatch.c
  ${root_dir}/src/core/nc_coap.c
  ${root_dir}/src/core/nc_coap_server.c
  ${root_dir}/src/core/nc_attacher_sct.c
  ${root_dir}/src/core/nc_coap_rest_error.c
  ${root_dir}/src/core/nc_rendezvous.c
  ${root_dir}/src/core/nc_stun.c
  ${root_dir}/src/core/nc_packet.c
  ${root_dir}/src/core/nc_keep_alive.c
  ${root_dir}/src/core/nc_attacher.c
  ${root_dir}/src/core/nc_version.c
  ${root_dir}/src/core/nc_stream.c
  ${root_dir}/src/core/nc_rendezvous_coap.c
  ${root_dir}/src/core/nc_stun_coap.c
  ${root_dir}/src/core/nc_stream_manager.c
  ${root_dir}/src/core/nc_coap_client.c
  ${root_dir}/src/core/nc_attacher_attach_end.c
  ${root_dir}/src/core/nc_dns_multi_resolver.c
  ${root_dir}/src/core/nc_device.c
)

set(ne_api
  ${root_dir}/src/api/nabto_device_events.c
  ${root_dir}/src/api/nabto_device_stream.c
  ${root_dir}/src/api/nabto_device_future_queue.c
  ${root_dir}/src/api/nabto_device.c
  ${root_dir}/src/api/nabto_device_authorization.c
  ${root_dir}/src/api/nabto_device_authorization_events.c
  ${root_dir}/src/api/nabto_device_logging.c
  ${root_dir}/src/api/nabto_device_experimental.c
  ${root_dir}/src/api/nabto_device_util.c
  ${root_dir}/src/api/nabto_device_event_handler.c
  ${root_dir}/src/api/nabto_device_connection_events.c
  ${root_dir}/src/api/nabto_device_coap.c
  ${root_dir}/src/api/nabto_device_future.c
  ${root_dir}/src/api/nabto_device_tcp_tunnelling.c
  ${root_dir}/src/api/nabto_device_error.c
  ${root_dir}/src/api/nabto_device_integration.c
  )

set(ne_api_test
  ${root_dir}/src/api_test/nabto_device_test_logging.c
  ${root_dir}/src/api_test/nabto_device_test_future_resolve.c
  ${root_dir}/src/api_test/nabto_device_test_event_queue.c
  ${root_dir}/src/api_test/nabto_device_test_timestamp.c
  ${root_dir}/src/api_test/nabto_device_test_dns.c
  )

set(ne_tinycbor
  ${root_dir}/3rdparty/tinycbor/tinycbor/src/cborparser_dup_string.c
  ${root_dir}/3rdparty/tinycbor/tinycbor/src/cbortojson.c
  ${root_dir}/3rdparty/tinycbor/tinycbor/src/cborencoder.c
  ${root_dir}/3rdparty/tinycbor/tinycbor/src/cborparser.c
  ${root_dir}/3rdparty/tinycbor/tinycbor/src/cborvalidation.c
  ${root_dir}/3rdparty/tinycbor/extra/cbor_extra.c
  ${root_dir}/3rdparty/tinycbor/extra/cbor_encode_encoded_cbor.c
)

set(ne_mbedtls
  ${root_dir}/3rdparty/mbedtls/mbedtls/aes.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/aesni.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/asn1parse.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/asn1write.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/base64.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/bignum.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/ccm.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/cipher.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/cipher_wrap.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/cmac.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/ctr_drbg.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/des.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/dhm.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/ecdh.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/ecdsa.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/ecp.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/ecp_curves.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/entropy.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/entropy_poll.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/error.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/havege.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/hmac_drbg.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/md.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/md_wrap.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/oid.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/pem.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/pk.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/pk_wrap.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/pkparse.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/pkwrite.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/platform.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/platform_util.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/sha256.c
)

set(ne_required
  ${ne_utils}
  ${ne_streaming}
  ${ne_mdns}
  ${ne_coap}
  ${ne_platform}
  ${ne_core}
  ${ne_api}
  ${ne_tinycbor}
)

set(ne_include_dirs
  ${root_dir}/include
)

set(ne_priv_include_dirs
  ${root_dir}/
  ${root_dir}/src
  ${root_dir}/nabto-common-cpp/src
  ${root_dir}/3rdparty/tinycbor/extra
  ${root_dir}/3rdparty/tinycbor/tinycbor/src
)
