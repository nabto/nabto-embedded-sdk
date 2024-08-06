find_package( Threads )
find_package( Boost REQUIRED COMPONENTS system asio)

set(CMAKE_CXX_STANDARD 14)
set(src
  platform_integration_stub.cpp
  ../test_cpp/util/io_service.cpp
  ../nabto-common/components/nn/src/nn/log.c
  ../test_cpp/util/tcp_echo_server.cpp
  )

include_directories(../test_cpp)
include_directories(../nabto-common/components/nn/include)

add_executable(platform_integration_stub ${src})
target_link_libraries(platform_integration_stub Boost::system Boost::asio ${CMAKE_THREAD_LIBS_INIT})
set_property(TARGET platform_integration_stub PROPERTY
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

install(TARGETS platform_integration_stub
  RUNTIME DESTINATION bin
  )
