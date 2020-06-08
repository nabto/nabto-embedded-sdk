set(src
  udp_server.cpp
  )

add_library(udp_server_cpp ${src})
include_directories(../../)

target_link_libraries(udp_server_cpp 3rdparty_boost_asio)
