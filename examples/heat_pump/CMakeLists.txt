find_package( Threads )

set(src
  ${ne_iam_src}
  src/heat_pump_main.c
  src/heat_pump.c
  src/heat_pump_state.c
  src/heat_pump_coap_handler.c
  src/heat_pump_get.c
  src/heat_pump_set_mode.c
  src/heat_pump_set_power.c
  src/heat_pump_set_target.c
  )

add_executable(heat_pump_device ${src})

target_link_libraries(heat_pump_device nabto_device_static 3rdparty_tinycbor 3rdparty_gopt 3rdparty_cjson nn apps_common)

#target_link_libraries( heat_pump_device ${CMAKE_THREAD_LIBS_INIT} )

install(TARGETS heat_pump_device
  RUNTIME DESTINATION bin
  )
