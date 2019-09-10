set(src
  json_config.cpp
  coap_request_handler.cpp
  )

add_library(device_examples_common "${src}")
target_link_libraries(device_examples_common 3rdparty_json)
target_include_directories(device_examples_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
