set(src
  src/heatpump.cpp
  src/heatpump_config.cpp
  src/heatpump_application.cpp
  )

add_executable(heatpump ${src})
target_link_libraries(heatpump nabto_device 3rdparty_gopt 3rdparty_json 3rdparty_cxxopts)
