set(root_dir ${CMAKE_CURRENT_LIST_DIR})

message("Using embedded dir:" ${root_dir})



set(ne_nn_src
  ${root_dir}/nabto-common/components/nn/src/nn/llist.c
  ${root_dir}/nabto-common/components/nn/src/nn/vector.c
  ${root_dir}/nabto-common/components/nn/src/nn/string_set.c
  ${root_dir}/nabto-common/components/nn/src/nn/log.c
  ${root_dir}/nabto-common/components/nn/src/nn/string_map.c
  )

set(ne_utils_src
  ${root_dir}/nabto-common/components/stun/src/nabto_stun_log.c
  ${root_dir}/nabto-common/components/stun/src/nabto_stun_client.c
  ${root_dir}/nabto-common/components/stun/src/nabto_stun_message.c
)


set(ne_streaming_src
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

set(ne_coap_src
  ${root_dir}/nabto-common/components/coap/src/nabto_coap.c
  ${root_dir}/nabto-common/components/coap/src/nabto_coap_client_impl.c
  ${root_dir}/nabto-common/components/coap/src/nabto_coap_server_impl_incoming.c
  ${root_dir}/nabto-common/components/coap/src/nabto_coap_server_impl.c
)

set(ne_platform_src
  ${root_dir}/src/platform/np_error_code.c
  ${root_dir}/src/platform/np_completion_event.c
  ${root_dir}/src/platform/np_logging.c
  ${root_dir}/src/platform/np_util.c
  ${root_dir}/src/platform/np_ip_address.c
  ${root_dir}/src/platform/np_udp_wrapper.c
  ${root_dir}/src/platform/np_event_queue_wrapper.c
  ${root_dir}/src/platform/np_timestamp_wrapper.c
  ${root_dir}/src/platform/np_dns_wrapper.c
  ${root_dir}/src/platform/np_tcp_wrapper.c
  ${root_dir}/src/platform/np_local_ip_wrapper.c
)

set(ne_core_src
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

set(ne_api_src
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

set(ne_api_test_src
  ${root_dir}/src/api_test/nabto_device_test.c
  ${root_dir}/src/api_test/nabto_device_test_logging.c
  ${root_dir}/src/api_test/nabto_device_test_future_resolve.c
  ${root_dir}/src/api_test/nabto_device_test_event_queue.c
  ${root_dir}/src/api_test/nabto_device_test_timestamp.c
  ${root_dir}/src/api_test/nabto_device_test_dns.c
  ${root_dir}/src/api_test/nabto_device_test_udp.c
  ${root_dir}/src/api_test/nabto_device_test_tcp.c
  ${root_dir}/src/api_test/nabto_device_test_local_ip.c
  )

set(ne_tinycbor_src
  ${root_dir}/3rdparty/tinycbor/tinycbor/src/cborparser_dup_string.c
  #${root_dir}/3rdparty/tinycbor/tinycbor/src/cbortojson.c
  ${root_dir}/3rdparty/tinycbor/tinycbor/src/cborencoder.c
  ${root_dir}/3rdparty/tinycbor/tinycbor/src/cborparser.c
  ${root_dir}/3rdparty/tinycbor/tinycbor/src/cborvalidation.c
  ${root_dir}/3rdparty/tinycbor/extra/cbor_extra.c
  ${root_dir}/3rdparty/tinycbor/extra/cbor_encode_encoded_cbor.c
)

set(ne_mbedtls_src
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/aes.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/aesni.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/asn1parse.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/asn1write.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/base64.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/bignum.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ccm.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/cipher.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/cipher_wrap.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/cmac.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ctr_drbg.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/des.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/dhm.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ecdh.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ecdsa.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ecp.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ecp_curves.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/entropy.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/entropy_poll.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/error.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/havege.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/hmac_drbg.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/md.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/md_wrap.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/oid.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/pem.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/pk.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/pk_wrap.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/pkparse.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/pkwrite.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/platform.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/platform_util.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/sha256.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/certs.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/x509.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/x509_create.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/x509_crt.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/x509write_crt.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/debug.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ssl_cache.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ssl_ciphersuites.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ssl_cli.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ssl_cookie.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ssl_srv.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ssl_ticket.c
  ${root_dir}/3rdparty/mbedtls/mbedtls/library/ssl_tls.c
)

set(ne_mbedtls_module_src
  ${root_dir}/src/modules/mbedtls/nm_mbedtls_timer.c
  ${root_dir}/src/modules/mbedtls/nm_mbedtls_util.c
  ${root_dir}/src/modules/mbedtls/nm_mbedtls_cli.c
  ${root_dir}/src/modules/mbedtls/nm_mbedtls_srv.c
  ${root_dir}/src/modules/mbedtls/nm_mbedtls_random.c
  )

set(ne_tcp_tunnels_src
  ${root_dir}/src/modules/tcp_tunnel/nm_tcp_tunnel_connection.c
  ${root_dir}/src/modules/tcp_tunnel/nm_tcp_tunnel_coap.c
  ${root_dir}/src/modules/tcp_tunnel/nm_tcp_tunnel.c
  )

set(ne_communication_buffer_src
  ${root_dir}/src/modules/communication_buffer/nm_communication_buffer.c
  )

set(ne_required_src
  ${ne_utils_src}
  ${ne_streaming_src}
  ${ne_mdns_src}
  ${ne_coap_src}
  ${ne_platform_src}
  ${ne_core_src}
  ${ne_api_src}
  ${ne_tinycbor_src}
  ${ne_nn_src}
  ${ne_mbedtls_src}
  ${ne_mbedtls_module_src}
  ${ne_tcp_tunnels_src}
  ${ne_communication_buffer_src}
)

set(ne_include_dirs
  ${root_dir}/include
)

set(ne_priv_include_dirs
#  ${root_dir}/
  ${root_dir}/src
  ${root_dir}/include
  ${root_dir}/nabto-common/components/coap/include
  ${root_dir}/nabto-common/components/streaming/include
  ${root_dir}/nabto-common/components/stun/include
  ${root_dir}/nabto-common/components/nn/include
  ${root_dir}/3rdparty/tinycbor/extra
  ${root_dir}/3rdparty/tinycbor/tinycbor/src
  ${root_dir}/3rdparty/mbedtls/mbedtls/include
  ${root_dir}/3rdparty/mbedtls/config
)
