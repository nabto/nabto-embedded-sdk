project(cmake_fetchcontent)

cmake_minimum_required(VERSION 3.24)

include(FetchContent)
SET(FETCHCONTENT_TRY_FIND_PACKAGE_MODE ALWAYS)

FetchContent_Declare(
  NabtoEmbeddedSDK
  # GIT ...
  SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../..
)
FetchContent_MakeAvailable(NabtoEmbeddedSDK)

find_package(NabtoEmbeddedSDK REQUIRED)

add_executable(test test.c)
target_link_libraries(test NabtoEmbeddedSDK::nabto_device)
