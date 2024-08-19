cmake_minimum_required(VERSION 3.24)
project(test)

find_package(NabtoEmbeddedSDK REQUIRED)

add_executable(test test.c)

target_link_libraries(test NabtoEmbeddedSDK::nabto_device)

install(TARGETS test)
