set(src
  src/heatpump.c
  src/heatpump_config.c
  )

add_executable(heatpump ${src})
target_link_libraries(heatpump nabto_device)
