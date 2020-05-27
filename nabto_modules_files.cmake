
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

