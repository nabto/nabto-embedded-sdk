
set(ne_dir ${CMAKE_CURRENT_LIST_DIR})


# Nabto mbedtls wrapper
set(ne_mbedtls_wrapper ${ne_dir}/src/modules/mbedtls)
set(ne_dtls_common_src
  ${ne_mbedtls_wrapper}/nm_mbedtls_timer.c
  ${ne_mbedtls_wrapper}/nm_mbedtls_util.c
)

set(ne_dtls_cli_src
  ${ne_dtls_common_src}
  ${ne_mbedtls_wrapper}/nm_mbedtls_cli.c
  )

set(ne_dtls_srv_src
  ${ne_dtls_common_src}
  ${ne_mbedtls_wrapper}/nm_mbedtls_srv.c
  )

set(ne_mbedtls_random_src
  ${ne_mbedtls_wrapper}/nm_mbedtls_random.c
  )

# Nabto event queue
set(ne_eventqueue_dir ${ne_dir}/src/modules/event_queue)
set(ne_event_queue_src
  ${ne_eventqueue_dir}/nm_event_queue.c
  )

set(ne_thread_event_queue_src
  ${ne_eventqueue_dir}/thread_event_queue.c
  )

# Nabto communications buffer
set(ne_communication_buffer_dir ${ne_dir}/src/modules/communication_buffer)
set(ne_communication_buffer_src
  ${ne_communication_buffer_dir}/nm_communication_buffer.c
)

# Nabto common components
set(ne_nn_common_components ${ne_dir}/nabto-common/components/nn)
set(ne_nn_util_src
  ${ne_nn_common_components}/src/nn/vector.c
  ${ne_nn_common_components}/src/nn/string_set.c
  ${ne_nn_common_components}/src/nn/log.c
  ${ne_nn_common_components}/src/nn/llist.c
  ${ne_nn_common_components}/src/nn/string_map.c
)
set(ne_nn_common_components_include ${ne_nn_common_components}/include)

# Nabto dns posix impl.
set(ne_dns_dir ${ne_dir}/src/modules/dns)
set(ne_dns_src
  ${ne_dns_dir}/unix/nm_unix_dns.c
)

# Unix wrappers
set(ne_unix_dir ${ne_dir}/src/modules/unix/)

# Nabto mdns impl.
set(ne_mdns_dir ${ne_dir}/src/modules/mdns)
set(ne_mdns_src
  ${ne_mdns_dir}/nm_mdns_server.c
  ${ne_unix_dir}/nm_unix_mdns.c
)

# Nabto local ip implementation
set(ne_localip_src
  ${ne_unix_dir}/nm_unix_local_ip.c
)

# Nabto timestamp posix impl.
set(ne_timestamp_dir ${ne_dir}/src/modules/timestamp)
set(ne_timestamp_src
  ${ne_timestamp_dir}/unix/nm_unix_timestamp.c
)

# Nabto select unix impl.
set(ne_select_unix_dir ${ne_dir}/src/modules/select_unix)
set(ne_select_unix_src
  ${ne_select_unix_dir}/nm_select_unix.c
  ${ne_select_unix_dir}/nm_select_unix_udp.c
  ${ne_select_unix_dir}/nm_select_unix_tcp.c
)

# Nabto tcp tunnel impl.
set(ne_tcp_tunnel_dir ${ne_dir}/src/modules/tcp_tunnel)
set(ne_tcp_tunnel_src
  ${ne_tcp_tunnel_dir}/nm_tcp_tunnel_connection.c
  ${ne_tcp_tunnel_dir}/nm_tcp_tunnel_coap.c
  ${ne_tcp_tunnel_dir}/nm_tcp_tunnel.c
)



# Nabto iam impl.
set(ne_iam_dir ${ne_dir}/src/modules/iam)
set(ne_iam_src
  ${ne_iam_dir}/nm_iam.c
  ${ne_iam_dir}/nm_iam_role.c
  ${ne_iam_dir}/nm_iam_user.c
  ${ne_iam_dir}/nm_iam_to_json.c
  ${ne_iam_dir}/nm_iam_from_json.c
  ${ne_iam_dir}/nm_iam_list_users.c
  ${ne_iam_dir}/nm_iam_pairing_get.c
  ${ne_iam_dir}/nm_iam_pairing_password.c
  ${ne_iam_dir}/nm_iam_pairing_local.c
  ${ne_iam_dir}/nm_iam_auth_handler.c
  ${ne_iam_dir}/nm_iam_coap_handler.c
  ${ne_iam_dir}/nm_iam_is_paired.c
  ${ne_iam_dir}/nm_iam_get_user.c
  ${ne_iam_dir}/nm_iam_delete_user.c
  ${ne_iam_dir}/nm_iam_list_roles.c
  ${ne_iam_dir}/nm_iam_remove_role_from_user.c
  ${ne_iam_dir}/nm_iam_add_role_to_user.c
  ${ne_iam_dir}/nm_iam_client_settings.c
)

# Nabto policies impl.
set(ne_policies_dir ${ne_dir}/src/modules/policies)
set(ne_policies_src
  ${ne_policies_dir}/nm_condition.c
  ${ne_policies_dir}/nm_statement.c
  ${ne_policies_dir}/nm_policy.c
  ${ne_policies_dir}/nm_policies_from_json.c
  ${ne_policies_dir}/nm_policies_to_json.c
)
