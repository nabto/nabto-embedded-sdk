set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(linux_src
  ${src_dir}/nabto_device.c
  ${src_dir}/nabto_device_stream.c
  ${src_dir}/nabto_device_coap.c
  ${src_dir}/nabto_device_future.c
  ${src_dir}/nabto_api_future_queue.c
  ${src_dir}/nabto_linux_platform.c
  )

add_library( nabto_device SHARED "${linux_src}")

target_link_libraries( nabto_device
  np_platform
  nm_unix_logging
  nm_epoll
  nm_unix_communication_buffer
  nm_unix_timestamp
  nm_dtls_cli
  nm_dtls_srv
  nm_unix_dns
  nc_core
  )

set_target_properties(nabto_device PROPERTIES PUBLIC_HEADER "../../include/nabto/nabto_device.h")

#set (CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libnabto_device.version")
#set_target_properties(nabto_device PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libnabto_device.version)

install(TARGETS nabto_device
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include/nabto
  )
