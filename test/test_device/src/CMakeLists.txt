find_package(MbedTLS COMPONENTS mbedtls mbedcrypto mbedx509)
find_package(nlohmann_json REQUIRED)
find_package(cxxopts)
set (CMAKE_CXX_STANDARD 14)

set(src
  test_device.cpp
  )

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_executable(test_device ${src})
target_link_libraries(test_device nabto_device common_util MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509 nlohmann_json::nlohmann_json cxxopts::cxxopts device_examples_common http_server)
