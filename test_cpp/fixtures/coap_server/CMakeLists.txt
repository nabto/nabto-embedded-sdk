find_package(Boost COMPONENTS system asio)
find_package(NabtoCommon REQUIRED)
set(coap_src
  coap_server.cpp
  )

add_library(coap_server_cpp "${coap_src}")

target_include_directories(coap_server_cpp PUBLIC "${CMAKE_CURRENT_LIST_DIR}/../..")
target_link_libraries(coap_server_cpp NabtoCommon::nabto_coap NabtoCommon::nn Boost::system Boost::asio)
