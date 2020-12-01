set(src
    simple_tunnel_device.c
)

add_executable(simple_tunnel_device "${src}")
target_link_libraries(simple_tunnel_device nabto_device_static apps_common)
