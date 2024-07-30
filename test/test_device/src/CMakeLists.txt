find_package(MbedTLS COMPONENTS mbedtls mbedcrypto mbedx509)
set (CMAKE_CXX_STANDARD 14)

set(src
  test_device.cpp
  )

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(test_device ${src})
target_link_libraries(test_device nabto_device common_util MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509 3rdparty_json 3rdparty_cxxopts device_examples_common http_server)
