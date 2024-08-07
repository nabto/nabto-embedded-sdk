find_package( Threads )
find_package(MbedTLS REQUIRED COMPONENTS mbedtls mbedcrypto mbedx509)
find_package(TinyCBOR REQUIRED)
find_package(NabtoCommon REQUIRED COMPONENTS nn nabto_stream mdns_server coap nabto_stun_client)
find_package(Libevent COMPONENTS core extra)



include_directories(${EVENT__INCLUDE_DIRS})

set(src
  nabto_platform_libevent.c
  libevent_event_queue.c
  )

if (HAVE_PTHREAD_H)
  add_library(nabto_device_threads STATIC ../modules/threads/unix/nabto_device_threads_unix.c)
elseif(HAVE_WINDOWS_H)
  add_library(nabto_device_threads STATIC ../modules/threads/windows/nabto_device_threads_win.c)
else()
  message(error "missing thread library")
endif()

target_link_libraries(nabto_device_threads PUBLIC NabtoCommon::nn)

set(nabto_device_dependencies
  $<TARGET_OBJECTS:nc_core>
  $<TARGET_OBJECTS:np_platform>
  $<TARGET_OBJECTS:nm_mdns>
  $<TARGET_OBJECTS:nm_tcp_tunnel>
  $<TARGET_OBJECTS:nm_logging_api>
  $<TARGET_OBJECTS:nabto_device_threads>
  $<TARGET_OBJECTS:nm_event_queue>
  $<TARGET_OBJECTS:nm_communication_buffer>
  $<TARGET_OBJECTS:nm_libevent>

  )

if (NABTO_DEVICE_MBEDTLS)
  list(APPEND nabto_device_dependencies
    $<TARGET_OBJECTS:nm_mbedtls_cli>
    $<TARGET_OBJECTS:nm_mbedtls_srv>
    $<TARGET_OBJECTS:nm_mbedtls_random>
    $<TARGET_OBJECTS:nm_mbedtls_spake2>
    $<TARGET_OBJECTS:nm_mbedtls_common>
  )
endif()

if(NABTO_DEVICE_WOLFSSL)
  list(APPEND nabto_device_dependencies
    $<TARGET_OBJECTS:nm_wolfssl_cli>
    $<TARGET_OBJECTS:nm_wolfssl_srv>
    $<TARGET_OBJECTS:nm_wolfssl_random>
    $<TARGET_OBJECTS:nm_wolfssl_spake2>
  )
endif()

add_library( nabto_device "${src}" "${ne_api_src}" "${ne_api_future_queue_src}" "${ne_api_test_src}" "${nabto_device_dependencies}")

if (BUILD_SHARED_LIBS)
  target_compile_definitions(nabto_device PRIVATE NABTO_DEVICE_API_EXPORTS)
  target_compile_definitions(nabto_device PRIVATE NABTO_DEVICE_API_SHARED)
else()
  target_compile_definitions(nabto_device PUBLIC NABTO_DEVICE_WIN32_API_STATIC)
endif()

target_link_libraries( nabto_device PRIVATE
  NabtoCommon::nn
  NabtoCommon::nabto_mdns
  NabtoCommon::nabto_stream
  NabtoCommon::nabto_coap
  NabtoCommon::nabto_stun
)

if (NABTO_DEVICE_MBEDTLS)
  target_link_libraries(nabto_device PRIVATE
    MbedTLS::mbedtls
    MbedTLS::mbedcrypto
    MbedTLS::mbedx509
    )
endif()

if (NABTO_DEVICE_WOLFSSL)
  target_link_libraries(nabto_device PRIVATE wolfssl)
endif()

target_link_libraries( nabto_device PRIVATE ${CMAKE_THREAD_LIBS_INIT} )

target_link_libraries(nabto_device PRIVATE libevent::core libevent::extra TinyCBOR::tinycbor)
target_link_libraries(nabto_device PRIVATE NabtoCommon::nn)

if (HAVE_WINDOWS_H)
  target_link_libraries(nabto_device PRIVATE ws2_32)
else()
  target_link_libraries(nabto_device PRIVATE libevent::pthreads)
endif()

target_include_directories(nabto_device
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

target_sources(nabto_device PUBLIC
    FILE_SET public_headers
    TYPE HEADERS
    BASE_DIRS ../../include
    FILES
        ../../include/nabto/nabto_device.h
        ../../include/nabto/nabto_device_experimental.h
        ../../include/nabto/nabto_device_virtual.h
        ../../include/nabto/nabto_device_test.h
        ../../include/nabto/nabto_device_config.h
)


# install(TARGETS nabto_device
#   EXPORT nabto_device
#   RUNTIME DESTINATION bin
#   LIBRARY DESTINATION lib
#   ARCHIVE DESTINATION lib
#   PUBLIC_HEADER DESTINATION include/nabto
#   )

# install(EXPORT nabto_device
#   FILE NabtoEmbeddedSDKTargets.cmake
#   NAMESPACE NabtoEmbeddedSDK::
#   DESTINATION lib/cmake/nabto_client)

# include(CMakePackageConfigHelpers)
# # generate the config file that includes the exports
#   configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/Config.cmake.in
#     "${CMAKE_CURRENT_BINARY_DIR}/NabtoEmbeddedSDKConfig.cmake"
#     INSTALL_DESTINATION "lib/cmake/NabtoEmbeddedSDK"
#     NO_SET_AND_CHECK_MACRO
#     NO_CHECK_REQUIRED_COMPONENTS_MACRO
#   )


set(integration_test_src
    nabto_device_libevent_integration_test.cpp
  )

if (DEVICE_BUILD_TESTS)
  add_executable(nabto_device_libevent_integration_test ${integration_test_src})
  target_include_directories(nabto_device_libevent_integration_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../test_cpp)
  target_link_libraries(nabto_device_libevent_integration_test nabto_device test_util)
endif()
