set(src
  src/hello_world.c
  )

add_executable(hello_world_device "${src}")
target_link_libraries(hello_world_device nabto_device)
