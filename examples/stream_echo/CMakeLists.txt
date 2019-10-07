set(src
  src/stream_echo_device.cpp
  )

add_executable(stream_echo_device "${src}")
target_link_libraries(stream_echo_device nabto_device 3rdparty_tinycbor 3rdparty_json 3rdparty_cxxopts device_examples_common)
