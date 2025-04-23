set(src
  custom_allocator_device.c
  ../../3rdparty/tinyalloc/tinyalloc/tinyalloc.c
  )

add_executable(custom_allocator_device "${src}")
target_link_libraries(custom_allocator_device nabto_device apps_common nm_fs_posix)

if(WIN32)
  # tinyalloc does some magic arithmetic using unary minus on an unsigned type.
  target_compile_definitions(custom_allocator_device PUBLIC "/wd4146")
endif(WIN32)

install(TARGETS custom_allocator_device
  RUNTIME DESTINATION bin
  )
