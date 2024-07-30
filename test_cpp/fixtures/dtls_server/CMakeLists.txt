find_package(MbedTLS COMPONENTS mbedtls mbedcrypto mbedx509)
find_package(Boost COMPONENTS asio)

set(src
  dtls_server.cpp
  dtls_server_impl.cpp
  mbedtls_util.cpp
  mbedtls_timer.cpp
  sha256.cpp
  certificate_context.cpp
  keep_alive.cpp
  )

add_library(dtls_server_cpp ${src})
include_directories(../../)

target_link_libraries(dtls_server_cpp udp_server_cpp coap coap_server_cpp Boost::asio MbedTLS::mbedtls MbedTLS::mbedcrypto MbedTLS::mbedx509 )
