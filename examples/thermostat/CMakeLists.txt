find_package( Threads )
find_package( TinyCBOR REQUIRED )
find_package( cJSON REQUIRED )
find_package( NabtoCommon REQUIRED)

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
  src/cbor_extra.c
  )

add_executable(thermostat_device ${src})

target_link_libraries(thermostat_device nabto_device 3rdparty_gopt cjson NabtoCommon::nn apps_common nm_fs_posix)

target_link_libraries(thermostat_device TinyCBOR::tinycbor)

#target_link_libraries( thermostat_device ${CMAKE_THREAD_LIBS_INIT} )

install(TARGETS thermostat_device
  RUNTIME DESTINATION bin
  )
