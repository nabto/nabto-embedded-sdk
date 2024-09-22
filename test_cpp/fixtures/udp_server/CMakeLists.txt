find_package(Boost COMPONENTS asio)

set(src
  udp_server.cpp
  )

add_library(udp_server_cpp ${src})
include_directories(../../)

target_link_libraries(udp_server_cpp Boost::asio)
