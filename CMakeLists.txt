cmake_minimum_required(VERSION 3.2)
project(nabto-embedded-sdk)

cmake_policy(SET CMP0063 NEW)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
include(CheckIncludeFiles)

# build all of nabto on linux, windows, mac
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_definitions(-DNODEFAULTLIB)
add_definitions(-DBOOST_ALL_NO_LIB)

option(DEVICE_BUILD_EXAMPLES "build device examples" ON)
option(DEVICE_BUILD_TESTS "build device tests" ON)
option(DEVICE_BUILD_APPS "build applications" ON)

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR}/src)

if ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
  include_directories(src/types/linux)
  add_definitions("-Wall")
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
  set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out CACHE STRING "" )
  set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out CACHE STRING "" )
  include_directories(src/types/linux)
  add_definitions("/W4")
  add_definitions(-DWIN32_LEAN_AND_MEAN)
  add_definitions(-D_CRT_NOSTDC_NO_DEPRECATE)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-D_SCL_SECURE_NO_WARNINGS)
  add_definitions(-DWINVER=0x0601)
  add_definitions(-D_WIN32_WINNT=0x0601)
  add_definitions(/wd4996)
  add_definitions(/wd4214)
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  include_directories(src/types/linux)
  add_compile_options(-Wall)
  add_compile_options(-Werror)
endif()

#CHECK_INCLUDE_FILES("sys/epoll.h" HAVE_SYS_EPOLL_H)
CHECK_INCLUDE_FILES("event2/event.h" HAVE_LIBEVENT_HEADERS)
CHECK_INCLUDE_FILES("sys/socket.h" HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILES("netinet/in.h" HAVE_NETINET_IN_H)
CHECK_INCLUDE_FILES("unistd.h" HAVE_UNISTD_H)
CHECK_INCLUDE_FILES("winsock2.h" HAVE_WINSOCK2_H)
CHECK_INCLUDE_FILES("io.h" HAVE_IO_H)
CHECK_INCLUDE_FILES("pthread.h" HAVE_PTHREAD_H)
CHECK_INCLUDE_FILES("windows.h" HAVE_WINDOWS_H)
CHECK_INCLUDE_FILES("ifaddrs.h" HAVE_IFADDRS_H)
CHECK_INCLUDE_FILES("net/if.h" HAVE_NET_IF_H)
CHECK_INCLUDE_FILES("arpa/inet.h" HAVE_ARPA_INET_H)
CHECK_INCLUDE_FILES("fcntl.h" HAVE_FCNTL_H)


find_package(Libevent REQUIRED)

if (HAVE_SYS_SOCKET_H)
  add_definitions(-DHAVE_SYS_SOCKET_H)
endif()

if (HAVE_NETINET_IN_H)
  add_definitions(-DHAVE_NETINET_IN_H)
endif()

if (HAVE_UNISTD_H)
  add_definitions(-DHAVE_UNISTD_H)
endif()

if (HAVE_WINSOCK2_H)
  add_definitions(-DHAVE_WINSOCK2_H)
endif()

if (HAVE_IO_H)
  add_definitions(-DHAVE_IO_H)
endif()

#if (HAVE_SYS_EPOLL_H)
#  add_definitions(-DHAVE_EPOLL)
#endif()

if (Libevent_FOUND)
  set(HAVE_LIBEVENT true)
  add_definitions(-DHAVE_LIBEVENT)
endif()

if (HAVE_PTHREAD_H)
  add_definitions(-DHAVE_PTHREAD_H)
endif()

if (HAVE_WINDOWS_H)
  add_definitions(-DHAVE_WINDOWS_H)
endif()

if (HAVE_IFADDRS_H)
  add_definitions(-DHAVE_IFADDRS_H)
endif()

if (HAVE_NET_IF_H)
  add_definitions(-DHAVE_NET_IF_H)
endif()

if (HAVE_ARPA_INET_H)
  add_definitions(-DHAVE_ARPA_INET_H)
endif()

if (HAVE_FCNTL_H)
  add_definitions(-DHAVE_FCNTL_H)
endif()

include_directories(src)
include_directories(include)

include_directories(nabto-common-cpp/src)





#if (HAVE_SYS_EPOLL_H)
#  add_subdirectory(src/modules/epoll)
#endif()

if (Libevent_FOUND)
  add_subdirectory(src/modules/libevent)
endif()

include_directories(LIBEVENT_INCLUDE_DIRS)

add_subdirectory(src/platform)
add_subdirectory(src/core)
add_subdirectory(src/api)

set(CMAKE_BUILD_TYPE Debug)

set(test_runner_src
  ${CMAKE_CURRENT_SOURCE_DIR}/test/runner/linux.c
  )

add_subdirectory(src/modules/communication_buffer)
add_subdirectory(src/modules/dtls)
add_subdirectory(3rdparty/mbedtls)
add_subdirectory(3rdparty/cjson)
add_subdirectory(3rdparty/gopt)
add_subdirectory(3rdparty/tinycbor)
add_subdirectory(3rdparty/nlohmann-json)
add_subdirectory(3rdparty/cxxopts)
add_subdirectory(3rdparty/nn)
add_subdirectory(nabto-common-cpp/src/streaming)
add_subdirectory(nabto-common-cpp/src/stun)
add_subdirectory(nabto-common-cpp/src/coap)
add_subdirectory(nabto-common-cpp/src/mdns)

add_subdirectory(src/modules/logging/api)
add_subdirectory(src/modules/mdns)
add_subdirectory(src/modules/tcp_tunnel)
add_subdirectory(src/modules/logging/test)
add_subdirectory(src/modules/policies)
add_subdirectory(src/modules/iam)
add_subdirectory(apps/common)

if (HAVE_SYS_SOCKET_H)
  add_subdirectory(src/modules/select_unix)
  add_subdirectory(src/modules/posix)
  add_definitions(-DHAVE_SELECT_UNIX)
endif()

if ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
  add_subdirectory(src/modules/dns/unix)
  add_subdirectory(src/modules/timestamp/unix)
  add_subdirectory(src/modules/logging/unix)
  add_subdirectory(src/modules/unix)
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
#  add_subdirectory(src/modules/logging/win)
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  add_subdirectory(src/modules/logging/unix)
  add_subdirectory(src/modules/dns/unix)
  add_subdirectory(src/modules/timestamp/unix)
  add_subdirectory(src/modules/unix)
endif()

if (DEVICE_BUILD_TESTS)
#  add_subdirectory(nabto-common-cpp/src/http_server)
  #add_subdirectory(test)

  if ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
    add_executable(unit_test "${test_runner_src}")

    target_link_libraries(unit_test
      np_platform_test
      np_platform
      nc_core
      nm_logging_unix)

    install(TARGETS unit_test
      RUNTIME DESTINATION bin
      )

  endif()

  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/test)
  add_subdirectory(test_cpp)
endif()

if (DEVICE_BUILD_EXAMPLES OR DEVICE_BUILD_APPS)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR})
  #add_subdirectory(apps/common)
endif()

if (DEVICE_BUILD_EXAMPLES)
#  add_subdirectory(examples/common)
#  add_subdirectory(examples/heat_pump)
#  add_subdirectory(examples/stream_echo)
#  add_subdirectory(examples/hello_world)
endif()

if (DEVICE_BUILD_APPS)
  add_subdirectory(apps/tcp_tunnel_device)
endif()
