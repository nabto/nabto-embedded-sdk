set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(src
  ${src_dir}/nc_attacher.c
  ${src_dir}/nc_packet.c
  ${src_dir}/nc_keep_alive.c
  ${src_dir}/nc_client_connect.c
  ${src_dir}/nc_client_connect_dispatch.c
  ${src_dir}/nc_stream_manager.c
  ${src_dir}/nc_stream.c
  ${src_dir}/nc_udp_dispatch.c
  ${src_dir}/nc_device.c
  ${src_dir}/nc_rendezvous.c
  ${src_dir}/nc_stun.c
  ${src_dir}/nc_coap_server.c
  ${src_dir}/nc_coap_client.c
  ${src_dir}/nc_coap_packet_printer.c
  ${src_dir}/nc_stun_coap.c
  ${src_dir}/nc_rendezvous_coap.c
  ${src_dir}/nc_iam.c
  )

set(test_src
  ${src_dir}/nc_attacher_test.c
  ${src_dir}/nc_client_connect_test.c
  ${src_dir}/nc_packet_test.c
  ${src_dir}/nc_keep_alive_test.c
  ${src_dir}/nc_stream_test.c
  ${src_dir}/nc_tests.c
  )

add_library( nc_core STATIC "${src}")

target_link_libraries( nc_core np_platform nabto_stream nabto_stun_client coap)

add_library( nc_core_test STATIC "${test_src}")

target_link_libraries( nc_core_test nm_timestamp nabto_stream nabto_stun_client)
