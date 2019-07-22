set(src
  src/main.cpp
  src/heat_pump.cpp
  src/heat_pump_config.cpp
  src/heat_pump_coap.cpp

  )

add_executable(heat_pump ${src})
target_link_libraries(heat_pump nabto_device 3rdparty_gopt 3rdparty_json 3rdparty_cxxopts)
