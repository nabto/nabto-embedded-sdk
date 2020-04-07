set(src
  nm_posix_udp.c
  )

add_library(nm_posix ${src})
target_link_libraries(nm_posix np_platform)
