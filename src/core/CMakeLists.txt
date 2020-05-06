
add_custom_target(GENERATE_VERSION ALL
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c
  COMMAND ${CMAKE_COMMAND} -P
  ${CMAKE_CURRENT_SOURCE_DIR}/version.cmake
  )

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(src
  ${src_dir}/nc_attacher.c
  ${src_dir}/nc_attacher_sct.c
  ${src_dir}/nc_attacher_attach_end.c
  ${src_dir}/nc_attacher_attach_start.c
  ${src_dir}/nc_packet.c
  ${src_dir}/nc_keep_alive.c
  ${src_dir}/nc_client_connection.c
  ${src_dir}/nc_client_connection_dispatch.c
  ${src_dir}/nc_stream_manager.c
  ${src_dir}/nc_stream.c
  ${src_dir}/nc_udp_dispatch.c
  ${src_dir}/nc_device.c
  ${src_dir}/nc_rendezvous.c
  ${src_dir}/nc_stun.c
  ${src_dir}/nc_coap_server.c
  ${src_dir}/nc_coap_client.c
  ${src_dir}/nc_coap.c
  ${src_dir}/nc_coap_packet_printer.c
  ${src_dir}/nc_coap_rest_error.c
  ${src_dir}/nc_stun_coap.c
  ${src_dir}/nc_rendezvous_coap.c
  ${src_dir}/nc_version.c
  ${src_dir}/nc_dns_resolver.c
  )

add_library( nc_core STATIC "${src}")

add_dependencies(nc_core GENERATE_VERSION)

target_link_libraries( nc_core np_platform nabto_stream nabto_stun_client coap 3rdparty_tinycbor)
