find_package(Libevent REQUIRED)

set(src
  nm_posix_udp.c
  nm_posix_get_local_ip.c
  nm_posix_mdns.c
  )

include_directories(${LIBEVENT_INCLUDE_DIRS})

add_library(nm_posix ${src})
target_link_libraries(nm_posix np_platform)
