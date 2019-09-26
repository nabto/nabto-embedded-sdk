set(src
  src/tcptunnel_device.cpp
  src/tcptunnel.cpp
  src/tcptunnel_coap.cpp
  )

add_executable(tcptunnel_device "${src}")
target_link_libraries(tcptunnel_device nabto_device 3rdparty_tinycbor 3rdparty_json 3rdparty_cxxopts device_examples_common)
