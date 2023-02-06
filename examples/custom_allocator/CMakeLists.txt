set(src
  custom_allocator_device.c
  ../../3rdparty/tinyalloc/tinyalloc/tinyalloc.c
  )

add_executable(custom_allocator_device "${src}")
target_link_libraries(custom_allocator_device nabto_device_static apps_common nm_fs_posix)

install(TARGETS custom_allocator_device
  RUNTIME DESTINATION bin
  )
