set(src_dir ${CMAKE_CURRENT_SOURCE_DIR})

set(nabto_device_src
  ${src_dir}/nabto_device.c
  ${src_dir}/nabto_device_stream.c
  ${src_dir}/nabto_device_coap.c
  ${src_dir}/nabto_device_future.c
  ${src_dir}/nabto_api_future_queue.c
  )

message(STATUS "host name: ${CMAKE_HOST_SYSTEM_NAME}")

if("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  if (ENV{HAS_EPOLL})
    set(nabto_device_src
      ${nabto_device_src}
      ${src_dir}/nabto_linux_platform.c
      ${src_dir}/nabto_device_threads_unix.c
      )
  else()
    set(nabto_device_src
      ${nabto_device_src}
      ${src_dir}/nabto_linux_select_platform.c
      ${src_dir}/nabto_device_threads_unix.c
      )
  endif()    
    
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
  set(nabto_device_src
    ${nabto_device_src}
    ${src_dir}/nabto_linux_platform.c
    ${src_dir}/nabto_device_threads_unix.c
    )
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
  set(nabto_device_src
    ${nabto_device_src}
    ${src_dir}/nabto_linux_select_platform.c
    ${src_dir}/nabto_device_threads_unix.c
    )
endif ()

add_library( nabto_device SHARED "${nabto_device_src}")

target_link_libraries( nabto_device
  np_platform
  nm_unix_logging
  nm_unix_communication_buffer
  nm_unix_timestamp
  nm_dtls_cli
  nm_dtls_srv
  nc_core
  )
    target_link_libraries( nabto_device
      nm_epoll
      nm_unix_dns
      )

if("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  if (ENV{HAS_EPOLL})
    target_link_libraries( nabto_device
      nm_epoll
      nm_unix_dns
      )
  else()
    target_link_libraries( nabto_device
      nm_select_unix
      nm_unix_dns
      )
  endif()    
    
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
    target_link_libraries( nabto_device
      nm_select_win
      nm_win_dns
      )
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
    target_link_libraries( nabto_device
      nm_select_unix
      nm_unix_dns
      )
endif ()

set_target_properties(nabto_device PROPERTIES PUBLIC_HEADER "../../include/nabto/nabto_device.h")

#set (CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS} "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/libnabto_device.version")
#set_target_properties(nabto_device PROPERTIES LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/libnabto_device.version)

install(TARGETS nabto_device
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  PUBLIC_HEADER DESTINATION include/nabto
  )
