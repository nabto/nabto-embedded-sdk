set(src
    simple_tunnel.c
)

add_executable(simple_tunnel "${src}")
target_link_libraries(simple_tunnel nabto_device_static apps_common)
