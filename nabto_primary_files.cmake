set(root_dir ${CMAKE_CURRENT_LIST_DIR})

message("Using embedded dir:" ${root_dir})



set(ne_nn_src
  ${root_dir}/nabto-common/components/nn/src/nn/allocator.c
  ${root_dir}/nabto-common/components/nn/src/nn/endian.c
  ${root_dir}/nabto-common/components/nn/src/nn/ip_address.c
  ${root_dir}/nabto-common/components/nn/src/nn/llist.c
  ${root_dir}/nabto-common/components/nn/src/nn/log.c
  ${root_dir}/nabto-common/components/nn/src/nn/set.c
  ${root_dir}/nabto-common/components/nn/src/nn/string_int_map.c
  ${root_dir}/nabto-common/components/nn/src/nn/string_map.c
  ${root_dir}/nabto-common/components/nn/src/nn/string_set.c
  ${root_dir}/nabto-common/components/nn/src/nn/string.c
  ${root_dir}/nabto-common/components/nn/src/nn/vector.c
)

set(ne_utils_src
  ${root_dir}/nabto-common/components/stun/src/nabto_stun_client.c
  ${root_dir}/nabto-common/components/stun/src/nabto_stun_message.c
)

set(ne_streaming_src
  ${root_dir}/nabto-common/components/streaming/src/nabto_stream_congestion_control.c
  ${root_dir}/nabto-common/components/streaming/src/nabto_stream_window.c
  ${root_dir}/nabto-common/components/streaming/src/nabto_stream_log_helper.c
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

set(ne_mdns_src
  ${root_dir}/nabto-common/components/mdns/src/mdns_server.c
)

set(ne_mdns_include_dir ${root_dir}/nabto-common/components/mdns/include)

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
  ${root_dir}/src/platform/np_mdns_wrapper.c
  ${root_dir}/src/platform/np_allocator.c
)

set(ne_core_src
  ${root_dir}/src/core/nc_connection.c
  ${root_dir}/src/core/nc_client_connection.c
  ${root_dir}/src/core/nc_virtual_connection.c
  ${root_dir}/src/core/nc_coap_packet_printer.c
  ${root_dir}/src/core/nc_attacher_attach_start.c
  ${root_dir}/src/core/nc_client_connection_dispatch.c
  ${root_dir}/src/core/nc_udp_dispatch.c
  ${root_dir}/src/core/nc_coap.c
  ${root_dir}/src/core/nc_coap_server.c
  ${root_dir}/src/core/nc_attacher_sct.c
  ${root_dir}/src/core/nc_attacher_fcm.c
  ${root_dir}/src/core/nc_attacher_service_invoke.c
  ${root_dir}/src/core/nc_attacher_ice_servers.c
  ${root_dir}/src/core/nc_coap_rest_error.c
  ${root_dir}/src/core/nc_rendezvous.c
  ${root_dir}/src/core/nc_stun.c
  ${root_dir}/src/core/nc_packet.c
  ${root_dir}/src/core/nc_keep_alive.c
  ${root_dir}/src/core/nc_attacher.c
  ${root_dir}/src/core/nc_attacher_watchdog.c
  ${root_dir}/src/core/nc_version.c
  ${root_dir}/src/core/nc_stream.c
  ${root_dir}/src/core/nc_virtual_stream.c
  ${root_dir}/src/core/nc_rendezvous_coap.c
  ${root_dir}/src/core/nc_stun_coap.c
  ${root_dir}/src/core/nc_stream_manager.c
  ${root_dir}/src/core/nc_coap_client.c
  ${root_dir}/src/core/nc_attacher_attach_end.c
  ${root_dir}/src/core/nc_dns_multi_resolver.c
  ${root_dir}/src/core/nc_device.c
  ${root_dir}/src/core/nc_spake2.c
  ${root_dir}/src/core/nc_spake2_coap.c
  ${root_dir}/src/core/nc_cbor.c
)

set(ne_api_src
  ${root_dir}/src/api/nabto_device_events.c
  ${root_dir}/src/api/nabto_device_stream.c
  ${root_dir}/src/api/nabto_device.c
  ${root_dir}/src/api/nabto_device_authorization.c
  ${root_dir}/src/api/nabto_device_authorization_events.c
  ${root_dir}/src/api/nabto_device_logging.c
  ${root_dir}/src/api/nabto_device_experimental.c
  ${root_dir}/src/api/nabto_device_experimental_set_private_key_secp256r1_mbedtls.c
  ${root_dir}/src/api/nabto_device_experimental_set_private_key_secp256r1_wolfssl.c
  ${root_dir}/src/api/nabto_device_fcm.c
  ${root_dir}/src/api/nabto_device_ice_servers.c
  ${root_dir}/src/api/nabto_device_service_invocation.c
  ${root_dir}/src/api/nabto_device_util.c
  ${root_dir}/src/api/nabto_device_listener.c
  ${root_dir}/src/api/nabto_device_connection_events.c
  ${root_dir}/src/api/nabto_device_virtual_connection.c
  ${root_dir}/src/api/nabto_device_coap.c
  ${root_dir}/src/api/nabto_device_future.c
  ${root_dir}/src/api/nabto_device_tcp_probe.c
  ${root_dir}/src/api/nabto_device_tcp_tunnelling.c
  ${root_dir}/src/api/nabto_device_error.c
  ${root_dir}/src/api/nabto_device_integration.c
  ${root_dir}/src/api/nabto_device_password_authentication.c
  ${root_dir}/src/api/nabto_device_internal.c
  ${root_dir}/src/api/nabto_device_crypto_speed_test.c
  ${root_dir}/src/api/nabto_device_mdns.c
  )

set(ne_api_future_queue_src
  ${root_dir}/src/api/nabto_device_future_queue.c
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
  ${root_dir}/src/api_test/nabto_device_test_mdns_publish_service.c
  )

set(ne_tinycbor_src
  ${root_dir}/3rdparty/tinycbor/tinycbor_src/src/cborparser_dup_string.c
  ${root_dir}/3rdparty/tinycbor/tinycbor_src/src/cborencoder.c
  ${root_dir}/3rdparty/tinycbor/tinycbor_src/src/cborparser.c
  ${root_dir}/3rdparty/tinycbor/tinycbor_src/src/cborvalidation.c
)

set(ne_cjson_dir ${CMAKE_CURRENT_LIST_DIR}/3rdparty/cjson)
set(ne_cjson_src
  ${ne_cjson_dir}/cjson/cJSON.c
)
set(ne_cjson_include_dir ${ne_cjson_dir})

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
  ${root_dir}/src/modules/mbedtls/nm_mbedtls_spake2.c
  )

set(ne_tcp_tunnels_src
  ${root_dir}/src/modules/tcp_tunnel/nm_tcp_tunnel_connection.c
  ${root_dir}/src/modules/tcp_tunnel/nm_tcp_tunnel_coap.c
  ${root_dir}/src/modules/tcp_tunnel/nm_tcp_tunnel.c
  )

set(ne_communication_buffer_src
  ${root_dir}/src/modules/communication_buffer/nm_communication_buffer.c
  )

set(ne_iam_src
  ${root_dir}/src/modules/iam/nm_iam.c
  ${root_dir}/src/modules/iam/nm_iam_role.c
  ${root_dir}/src/modules/iam/nm_iam_user.c
  ${root_dir}/src/modules/iam/nm_iam_to_json.c
  ${root_dir}/src/modules/iam/nm_iam_from_json.c
  ${root_dir}/src/modules/iam/nm_iam_auth_handler.c
  ${root_dir}/src/modules/iam/nm_iam_pake_handler.c
  ${root_dir}/src/modules/iam/nm_iam_connection_events.c
  ${root_dir}/src/modules/iam/nm_iam_configuration.c
  ${root_dir}/src/modules/iam/nm_iam_state.c
  ${root_dir}/src/modules/iam/nm_iam_serializer.c
  ${root_dir}/src/modules/iam/nm_iam_pairing.c
  ${root_dir}/src/modules/iam/nm_iam_internal.c
  ${root_dir}/src/modules/iam/nm_iam_allocator.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_coap_handler.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_pairing_get.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_pairing_password_open.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_pairing_password_invite.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_pairing_local_open.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_pairing_local_initial.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_get_notification_categories.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_send_fcm_test.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_list_users.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_get_me.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_get_user.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_create_user.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_delete_user.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_list_roles.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_set_user_role.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_set_user_name.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_set_user_display_name.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_set_user_fingerprint.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_add_user_fingerprint.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_delete_user_fingerprint.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_set_user_sct.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_set_user_password.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_set_user_fcm.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_set_user_notification_categories.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_set_user_oauth_subject.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_settings_get.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_settings_set.c
  ${root_dir}/src/modules/iam/coap_handler/nm_iam_device_info_set.c
  ${root_dir}/src/modules/iam/policies/nm_condition.c
  ${root_dir}/src/modules/iam/policies/nm_statement.c
  ${root_dir}/src/modules/iam/policies/nm_policy.c
  ${root_dir}/src/modules/iam/policies/nm_policies_from_json.c
  ${root_dir}/src/modules/iam/policies/nm_policies_to_json.c
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

set(ne_required_src_no_tls
  ${ne_utils_src}
  ${ne_streaming_src}
  ${ne_mdns_src}
  ${ne_coap_src}
  ${ne_platform_src}
  ${ne_core_src}
  ${ne_api_src}
  ${ne_tinycbor_src}
  ${ne_nn_src}
  ${ne_tcp_tunnels_src}
  ${ne_communication_buffer_src}
)

set(ne_coap_include_dirs
  ${root_dir}/nabto-common/components/coap/include
)
set(ne_stun_include_dirs
  ${root_dir}/nabto-common/components/stun/include
)
set(ne_streaming_include_dirs
  ${root_dir}/nabto-common/components/streaming/include
)
set(ne_nn_include_dirs
  ${root_dir}/nabto-common/components/nn/include
)
set(ne_mdns_include_dirs
  ${root_dir}/nabto-common/components/mdns/include
)

set(ne_include_dirs
  ${root_dir}/src
  ${root_dir}/include
)

set(ne_priv_include_dirs_no_tls
#  ${root_dir}/
  ${root_dir}/src
  ${root_dir}/include
  ${root_dir}/nabto-common/components/coap/include
  ${root_dir}/nabto-common/components/streaming/include
  ${root_dir}/nabto-common/components/stun/include
  ${root_dir}/nabto-common/components/nn/include
  ${root_dir}/nabto-common/components/mdns/include
  ${root_dir}/3rdparty/tinycbor/tinycbor_src/include/tinycbor
  ${root_dir}/3rdparty/tinycbor/tinycbor_src/include
)

set(ne_nn_include_dirs
  ${root_dir}/nabto-common/components/nn/include
)

set(ne_priv_include_dirs
#  ${root_dir}/
  ${root_dir}/src
  ${root_dir}/include
  ${root_dir}/nabto-common/components/coap/include
  ${root_dir}/nabto-common/components/streaming/include
  ${root_dir}/nabto-common/components/stun/include
  ${root_dir}/nabto-common/components/nn/include
  ${root_dir}/nabto-common/components/mdns/include
  ${root_dir}/3rdparty/tinycbor/tinycbor_src/include/tinycbor
  ${root_dir}/3rdparty/tinycbor/tinycbor_src/include
  ${root_dir}/3rdparty/mbedtls/mbedtls/include
  ${root_dir}/3rdparty/mbedtls/config
)
