set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(nabto_device_src
  ${src_dir}/nabto_device.c
  ${src_dir}/nabto_device_stream.c
  ${src_dir}/nabto_device_coap.c
  ${src_dir}/nabto_device_future.c
  ${src_dir}/nabto_api_future_queue.c
  ${src_dir}/nabto_device_error.c
  ${src_dir}/nabto_device_experimental.c
  )

message(STATUS "host name: ${CMAKE_HOST_SYSTEM_NAME}")

if("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  set(nabto_device_src
    ${nabto_device_src}
    ${src_dir}/nabto_platform.c
    ${src_dir}/unix/nabto_device_threads_unix.c
    )

elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
  set(nabto_device_src
    ${nabto_device_src}
    ${src_dir}/nabto_platform.c
    ${src_dir}/windows/nabto_device_threads_win.c
    )
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
  set(nabto_device_src
    ${nabto_device_src}
    ${src_dir}/nabto_platform.c
    ${src_dir}/unix/nabto_device_threads_unix.c
    )
endif ()

add_definitions(-DNABTO_DEVICE_CLIENT_API_EXPORTS)
add_library( nabto_device SHARED "${nabto_device_src}")

target_link_libraries( nabto_device
  np_platform
  nm_logging_api
  nm_unix_communication_buffer
  nm_access_control
  nm_timestamp
  nm_dtls_cli
  nm_dtls_srv
  nm_udp
  nm_dns
  nc_core
  nm_mdns
  )

set_target_properties(nabto_device PROPERTIES PUBLIC_HEADER "../../include/nabto/nabto_device.h")

#set (CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libnabto_device.version")
#set_target_properties(nabto_device PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libnabto_device.version)

install(TARGETS nabto_device
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include/nabto
  )
