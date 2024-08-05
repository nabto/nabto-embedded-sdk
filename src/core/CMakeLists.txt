find_package(TinyCBOR REQUIRED)
find_package(MbedTLS COMPONENTS mbedtls mbedcrypto mbedx509)
find_package(NabtoCommon COMPONENTS nabto_stream)


add_custom_target(GENERATE_VERSION ALL
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c
  COMMAND ${CMAKE_COMMAND} -P
  ${CMAKE_CURRENT_SOURCE_DIR}/version.cmake
  )

add_library( nc_core "${ne_core_src}")

add_dependencies(nc_core GENERATE_VERSION)

target_link_libraries( nc_core PUBLIC np_platform NabtoCommon::nabto_stream NabtoCommon::nabto_stun NabtoCommon::nabto_coap NabtoCommon::nn)

find_package(TinyCBOR REQUIRED)
target_link_libraries(nc_core PRIVATE TinyCBOR::tinycbor)

if (NABTO_DEVICE_MBEDTLS)
  target_link_libraries(nc_core PRIVATE MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509)
endif()
