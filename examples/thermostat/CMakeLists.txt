find_package( Threads )

set(src
  ${ne_iam_src}
  src/thermostat_main.c
  src/thermostat_file.c
  src/thermostat.c
  src/thermostat_iam.c
  src/thermostat_coap_handler.c
  src/thermostat_get.c
  src/thermostat_set_mode.c
  src/thermostat_set_power.c
  src/thermostat_set_target.c
  src/thermostat_state.c
  src/thermostat_state_file_backend.c
  src/thermostat_state_data.c
  )

add_executable(thermostat_device ${src})

target_link_libraries(thermostat_device nabto_device_static 3rdparty_tinycbor 3rdparty_gopt 3rdparty_cjson nn apps_common nm_fs_unix)

#target_link_libraries( thermostat_device ${CMAKE_THREAD_LIBS_INIT} )

install(TARGETS thermostat_device
  RUNTIME DESTINATION bin
  )
