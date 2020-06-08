find_package( Threads )

set(CMAKE_CXX_STANDARD 14)
set(src
  platform_integration_stub.cpp
  ../test_cpp/util/io_service.cpp
  )

include_directories(../test_cpp)

add_executable(platform_integration_stub ${src})
target_link_libraries(platform_integration_stub 3rdparty_boost_system ${CMAKE_THREAD_LIBS_INIT})
