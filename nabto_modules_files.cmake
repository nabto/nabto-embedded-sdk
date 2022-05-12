
set(ne_dir ${CMAKE_CURRENT_LIST_DIR})


# Nabto event queue
set(ne_eventqueue_dir ${ne_dir}/src/modules/event_queue)
set(ne_event_queue_src
  ${ne_eventqueue_dir}/nm_event_queue.c
  )

set(ne_thread_event_queue_src
  ${ne_eventqueue_dir}/thread_event_queue.c
  )

# Nabto dns posix impl.
set(ne_dns_dir ${ne_dir}/src/modules/dns)
set(ne_dns_src
  ${ne_dns_dir}/unix/nm_unix_dns.c
)

# Unix wrappers
set(ne_unix_dir ${ne_dir}/src/modules/unix/)

# Nabto mdns impl.
set(ne_modules_mdns_dir ${ne_dir}/src/modules/mdns)
set(ne_modules_mdns_src
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
  ${ne_select_unix_dir}/nm_select_unix_mdns_udp_bind.c
)


set(ne_modules_threads_unix_dir ${ne_dir}/src/modules/threads/unix)
set(ne_modules_threads_unix_src
  ${ne_modules_threads_unix_dir}/nabto_device_threads_unix.c
)

set(ne_modules_mdns_dir ${ne_dir}/src/modules/mdns)
set(ne_modules_mdns_src
  ${ne_modules_mdns_dir}/nm_mdns_server.c
)
