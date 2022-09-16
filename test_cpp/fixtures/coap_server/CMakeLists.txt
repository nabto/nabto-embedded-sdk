set(coap_src
  coap_server.cpp
  )

add_library(coap_server_cpp "${coap_src}")

target_include_directories(coap_server_cpp PUBLIC "${CMAKE_CURRENT_LIST_DIR}/../..")
target_link_libraries(coap_server_cpp coap nn 3rdparty_boost_system)
