
set(src
  )

if("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  set(src
    ${src}
    test_platform_linux.c
    )

elseif("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
  set(src
    ${src}
    test_platform_win.c
    )
elseif("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
  set(src
    ${src}
    test_platform_mac.c
    )
endif()

add_library( test_platform "${src}")

target_link_libraries( test_platform
  np_platform
  nm_logging_api
  nm_unix_communication_buffer
  nm_timestamp
  nm_dtls_cli
  nm_dtls_srv
  nm_dns
  nc_core
  nm_mdns
  )

if("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  target_link_libraries(test_platform nm_epoll)
elseif("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
  # TODOOOOOO
elseif("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
  target_link_libraries(test_platform nm_select_unix)
endif()
