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
  src/thermostat_history.c
  src/thermostat_stream.c
  src/thermostat_coap_history.c
  src/thermostat_coap_set_schedule.c
  src/cbor_extra.c
  )

add_executable(thermostat_device ${src})

target_link_libraries(thermostat_device nabto_device 3rdparty_gopt cjson NabtoCommon::nn apps_common nm_fs_posix)

target_link_libraries(thermostat_device TinyCBOR::tinycbor)

#target_link_libraries( thermostat_device ${CMAKE_THREAD_LIBS_INIT} )

install(TARGETS thermostat_device
  RUNTIME DESTINATION bin
  )

option(THERMOSTAT_BUILD_TESTS "Build the thermostat example tests" OFF)
if (THERMOSTAT_BUILD_TESTS)
  enable_testing()
  add_executable(thermostat_state_test test/state_test.c src/thermostat_state.c)
  target_include_directories(thermostat_state_test PRIVATE src)
  target_link_libraries(thermostat_state_test nabto_device TinyCBOR::tinycbor NabtoCommon::nn)
  add_test(NAME thermostat_state COMMAND thermostat_state_test)
  add_test(NAME thermostat_history COMMAND thermostat_history_test)
  add_executable(thermostat_history_test test/history_test.c src/thermostat_history.c)
  target_include_directories(thermostat_history_test PRIVATE src)
  if (UNIX)
    target_link_libraries(thermostat_history_test m pthread)
  endif()
endif()
