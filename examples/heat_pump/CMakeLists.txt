set (CMAKE_CXX_STANDARD 14)

find_package( Threads )

set(src
  src/main.cpp
  src/heat_pump.cpp
  src/heat_pump_coap.cpp
  src/heat_pump_iam_persisting.cpp
  )

add_executable(heat_pump_device ${src})
target_link_libraries(heat_pump_device nabto_device 3rdparty_tinycbor 3rdparty_gopt 3rdparty_json 3rdparty_cxxopts device_examples_common iam_cpp)

target_link_libraries( heat_pump_device ${CMAKE_THREAD_LIBS_INIT} )
