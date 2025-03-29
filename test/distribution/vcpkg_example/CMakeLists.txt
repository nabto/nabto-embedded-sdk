project(vcpkg_example)
find_package(NabtoEmbeddedSDK REQUIRED)

add_executable(vcpkg_example main.c)
target_link_libraries(vcpkg_example PRIVATE NabtoEmbeddedSDK::nabto_device)
