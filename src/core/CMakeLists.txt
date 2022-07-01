
add_custom_target(GENERATE_VERSION ALL
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c
  COMMAND ${CMAKE_COMMAND} -P
  ${CMAKE_CURRENT_SOURCE_DIR}/version.cmake
  )

add_library( nc_core STATIC "${ne_core_src}")

add_dependencies(nc_core GENERATE_VERSION)

target_link_libraries( nc_core np_platform nabto_stream nabto_stun_client coap 3rdparty_tinycbor nn)
if (NABTO_USE_MBEDTLS)
  target_link_libraries(nc_core 3rdparty_mbedtls)
endif()
