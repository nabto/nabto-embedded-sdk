cmake_minimum_required(VERSION 3.24)

# If a package is not found based on FetchContent OVERRIDE_FIND_PACKAGE or using
# a <package_name>Config.cmake file, these Find<Package>.cmake files will be
# used. This happens because we sets CMAKE_FIND_PACKAGE_PREFER_CONFIG ushc that
# config mode packages is preferred over the Find<package>.cmake scripts.
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/vcpkg;${CMAKE_MODULE_PATH}")

project(NabtoEmbeddedSDK VERSION 0.0.1)

set(CMAKE_POLICY_DEFAULT_CMP0063 NEW)
cmake_policy(SET CMP0063 NEW)
cmake_policy(SET CMP0090 NEW)
set(CMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY OFF)
#set(CMAKE_FIND_PACKAGE_PREFER_CONFIG ON) This fails if there are system installed packages with configuration files which shadows for locally installed packages using find_package.

set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

set(CMAKE_XCODE_GENERATE_SCHEME ON)
set(CMAKE_XCODE_SCHEME_ADDRESS_SANITIZER ON)
set(CMAKE_XCODE_SCHEME_ADDRESS_SANITIZER_USE_AFTER_RETURN ON)

include(CheckIncludeFiles)
include(CheckSymbolExists)
include(FetchContent)
include(${CMAKE_CURRENT_SOURCE_DIR}/nabto_primary_files.cmake)

message("CMake Version: ${CMAKE_VERSION}")

# build all of nabto on linux, windows, mac
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
#set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64" CACHE STRING "" FORCE)
add_definitions(-DNODEFAULTLIB)
add_definitions(-DBOOST_ALL_NO_LIB)
message("c++ compiler was LOADED. ${CMAKE_CXX_COMPILER_ID}")


option(DEVICE_BUILD_EXAMPLES "build device examples" ON)

option(DEVICE_BUILD_TESTS "build device tests" OFF)

option(DEVICE_BUILD_APPS "build applications" ON)

option(DEVICE_STATIC_LINK_VCRUNTIME "Static link visual c runtime" OFF)
option(DEVICE_MBEDTLS_2 "Set this to true if the device is built against mbedtls version 2" ON)

option(NABTO_DEVICE_PREFER_SYSTEM_LIBS "Prefer system libraries" OFF)

option(NABTO_DEVICE_USE_SYSTEM_MBEDTLS "use mbedtls from the system" ${NABTO_DEVICE_PREFER_SYSTEM_LIBS})
option(NABTO_DEVICE_USE_SYSTEM_TINYCBOR "use tinycbor from the system" ${NABTO_DEVICE_PREFER_SYSTEM_LIBS})
option(NABTO_DEVICE_USE_SYSTEM_NABTOCOMMON "use nabtocommon from the system" ${NABTO_DEVICE_PREFER_SYSTEM_LIBS})
option(NABTO_DEVICE_USE_SYSTEM_CJSON "use cjson from the system" ${NABTO_DEVICE_PREFER_SYSTEM_LIBS})
option(NABTO_DEVICE_USE_SYSTEM_BOOST "use boost from the system" ${NABTO_DEVICE_PREFER_SYSTEM_LIBS})
option(NABTO_DEVICE_USE_SYSTEM_NLOHMANNJSON "use nlohmann_json from the system" ${NABTO_DEVICE_PREFER_SYSTEM_LIBS})
option(NABTO_DEVICE_USE_SYSTEM_LIBEVENT "use libevent from the system" ${NABTO_DEVICE_PREFER_SYSTEM_LIBS})

set(NABTO_DEVICE_VERSION "" CACHE STRING "use this version instead of getting the version from the git tag")

if (DEVICE_STATIC_LINK_VCRUNTIME)
  cmake_policy(SET CMP0091 NEW)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_subdirectory(3rdparty/gopt)

if (NOT NABTO_DEVICE_USE_SYSTEM_TINYCBOR)
  FetchContent_Declare(
    TinyCBOR
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/tinycbor
    OVERRIDE_FIND_PACKAGE
  )
  FetchContent_MakeAvailable(TinyCBOR)
endif()

set(ENABLE_TESTING OFF CACHE BOOL "disable MbedTLS testing")
set(ENABLE_PROGRAMS OFF CACHE BOOL "disable MbedTLS programs")
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL OFF CACHE BOOL "disable mbedtls package config and install")

if (NOT NABTO_DEVICE_USE_SYSTEM_MBEDTLS)
  FetchContent_Declare(
    MbedTLS
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/mbedtls/mbedtls
    OVERRIDE_FIND_PACKAGE
  )
  FetchContent_MakeAvailable(MbedTLS)
endif()

if (NOT NABTO_DEVICE_USE_SYSTEM_LIBEVENT)
  add_subdirectory(3rdparty/libevent)
endif()

set(NN_BUILD_TESTS OFF CACHE BOOL "enable nn tests")

if (NOT NABTO_DEVICE_USE_SYSTEM_NABTOCOMMON)
  FetchContent_Declare(
    NabtoCommon
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/nabto-common
    OVERRIDE_FIND_PACKAGE
  )
  FetchContent_MakeAvailable(NabtoCommon)
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(BOOST_CONTEXT_ABI "sysv" CACHE STRING "boost context abi")
  set(BOOST_CONTEXT_ARCHITECTURE "combined" CACHE STRING "boost context architecture")
endif()

if (DEVICE_BUILD_TESTS)
  if (NOT NABTO_DEVICE_USE_SYSTEM_BOOST)
    message("Downloading boost libraries this can take some time")
    set(BOOST_INCLUDE_LIBRARIES asio system test)
    FetchContent_Declare(
      Boost
      URL https://github.com/boostorg/boost/releases/download/boost-1.85.0/boost-1.85.0-cmake.tar.xz
      #GIT_REPOSITORY https://github.com/boostorg/boost.git
      #GIT_TAG boost-1.85.0
      OVERRIDE_FIND_PACKAGE
    )
    FetchContent_MakeAvailable(Boost)
  endif()
endif()

if (NOT NABTO_DEVICE_USE_SYSTEM_CJSON)
  FetchContent_Declare(
    cJSON
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/cjson
    OVERRIDE_FIND_PACKAGE
  )
  FetchContent_MakeAvailable(cJSON)
endif()

if (NOT NABTO_DEVICE_USE_SYSTEM_NLOHMANNJSON)
  FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    OVERRIDE_FIND_PACKAGE
  )
  FetchContent_MakeAvailable(nlohmann_json)
endif()

set(src_dir ${CMAKE_CURRENT_SOURCE_DIR}/src)

if ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Darwin")
  add_definitions("-Wall")
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Windows")
  include(InstallRequiredSystemLibraries)
  set( CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out CACHE STRING "" )
  set( CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/out CACHE STRING "" )
  add_definitions("/W4")
  add_definitions(-DWIN32_LEAN_AND_MEAN)
  add_definitions(-D_CRT_NOSTDC_NO_DEPRECATE)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS)
  add_definitions(-D_SCL_SECURE_NO_WARNINGS)
  add_definitions(-DWINVER=0x0601)
  add_definitions(-D_WIN32_WINNT=0x0601)
  add_definitions(/wd4996)
  add_definitions(/wd4214)
  set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -latomic")
elseif ("x_${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "x_Linux")
  add_compile_options(-Wall)
  set(CMAKE_CXX_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -latomic")
endif()

CHECK_INCLUDE_FILES("event2/event.h" HAVE_LIBEVENT_HEADERS)
CHECK_INCLUDE_FILES("sys/socket.h" HAVE_SYS_SOCKET_H)
CHECK_INCLUDE_FILES("sys/select.h" HAVE_SYS_SELECT_H)
CHECK_INCLUDE_FILES("sys/time.h" HAVE_SYS_TIME_H)
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
CHECK_INCLUDE_FILES("netinet/tcp.h" HAVE_NETINET_TCP_H)

check_symbol_exists(timegm "time.h" HAVE_TIMEGM)

set(HAVE_LIBEVENT_HEADERS 1)
add_definitions(-DHAVE_LIBEVENT)

if (HAVE_SYS_SOCKET_H)
  add_definitions(-DHAVE_SYS_SOCKET_H)
endif()

if (HAVE_SYS_SELECT_H)
  add_definitions(-DHAVE_SYS_SELECT_H)
endif()

if (HAVE_SYS_TIME_H)
  add_definitions(-DHAVE_SYS_TIME_H)
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

if (HAVE_NETINET_TCP_H)
  add_definitions(-DHAVE_NETINET_TCP_H)
endif()

if (HAVE_TIMEGM)
  add_definitions(-DHAVE_TIMEGM)
endif()

if (DEVICE_MBEDTLS_2)
  add_definitions(-DDEVICE_MBEDTLS_2)
endif()

include_directories(src)
include_directories(include)

set(test_runner_src
  ${CMAKE_CURRENT_SOURCE_DIR}/test/runner/linux.c
  )

add_subdirectory(src/modules/communication_buffer)

option(NABTO_DEVICE_WOLFSSL "Use wolfssl as DTLS module instead of Mbedtls" OFF)
option(NABTO_DEVICE_DTLS_LOG "Enable logging for 3rd party DTLS module" OFF)
option(NABTO_DEVICE_DTLS_CLIENT_ONLY "Make device be dtls client for client connections" OFF)


if (NABTO_DEVICE_DTLS_LOG)
  add_definitions(-DNABTO_DEVICE_DTLS_LOG)
endif()

if (NABTO_DEVICE_DTLS_CLIENT_ONLY)
  add_definitions(-DNABTO_DEVICE_DTLS_CLIENT_ONLY)
endif()

if (NABTO_DEVICE_WOLFSSL)
    add_definitions(-DNABTO_DEVICE_WOLFSSL)
    add_subdirectory(src/modules/wolfssl)
else()
    set(NABTO_DEVICE_MBEDTLS TRUE)
    add_subdirectory(src/modules/mbedtls)
endif()


add_subdirectory(src/modules/mdns)
add_subdirectory(src/modules/tcp_tunnel)
add_subdirectory(src/modules/logging/test)
add_subdirectory(src/modules/iam)
add_subdirectory(src/modules/libevent)
add_subdirectory(src/modules/threads/unix)
add_subdirectory(src/modules/threads/windows)
add_subdirectory(src/modules/logging/api)
add_subdirectory(src/modules/fs/posix)
add_subdirectory(apps/common)

add_subdirectory(src/platform)
add_subdirectory(src/core)
add_subdirectory(src/api)
add_subdirectory(src/nabto_device_libevent)

if (HAVE_SYS_SELECT_H)
  add_subdirectory(src/modules/select_unix)
#  add_subdirectory(src/modules/unix)
  add_definitions(-DHAVE_SELECT_UNIX)
  set(HAVE_SELECT_UNIX 1)
endif()

if (UNIX)
  add_subdirectory(src/modules/dns/unix)
  add_subdirectory(src/modules/timestamp/unix)
  add_subdirectory(src/modules/logging/unix)
  add_subdirectory(src/modules/unix)
endif()

if (DEVICE_BUILD_TESTS)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/test)
  add_subdirectory(test_cpp)
  add_subdirectory(platform_integration_stub)
endif()

if (DEVICE_BUILD_EXAMPLES OR DEVICE_BUILD_APPS)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR})
  #add_subdirectory(apps/common)
endif()
add_subdirectory(src/modules/event_queue)

if (DEVICE_BUILD_EXAMPLES)
  if (NOT WIN32)

  add_subdirectory(platform_integration_example)
  endif()
  add_subdirectory(examples/thermostat)
  add_subdirectory(examples/simple_stream)
  add_subdirectory(examples/futures)
  add_subdirectory(examples/simple_coap)
  add_subdirectory(examples/simple_mdns)
  add_subdirectory(examples/simple_tunnel)
  add_subdirectory(examples/simple_push)
  add_subdirectory(examples/simple_service_invocation)
  add_subdirectory(examples/simple_speed_test)
  add_subdirectory(examples/simple_password_authentication)
  add_subdirectory(examples/custom_allocator)

#  add_subdirectory(platform_integration_guide)
endif()

if (DEVICE_BUILD_APPS)
  add_subdirectory(apps/tcp_tunnel_device)
endif()


include(GNUInstallDirs)
set(config_install_dir "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")

set(version_config "${generated_dir}/${PROJECT_NAME}ConfigVersion.cmake")
set(project_config "${generated_dir}/${PROJECT_NAME}Config.cmake")
set(TARGETS_EXPORT_NAME "${PROJECT_NAME}Targets")
set(namespace "${PROJECT_NAME}::")

include(CMakePackageConfigHelpers)

add_library(NabtoEmbeddedSDK::nabto_device ALIAS nabto_device)
add_library(NabtoEmbeddedSDK::nm_iam ALIAS nm_iam)
install(
    TARGETS nabto_device nm_iam
    EXPORT "${TARGETS_EXPORT_NAME}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    FILE_SET public_headers
)

write_basic_package_version_file(
    "${version_config}" COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
    "cmake-scripts/Config.cmake.in"
    "${project_config}"
    INSTALL_DESTINATION "${config_install_dir}"
)

# Config
#   * <prefix>/lib/cmake/Foo/FooConfig.cmake
#   * <prefix>/lib/cmake/Foo/FooConfigVersion.cmake
install(
    FILES "${project_config}" "${version_config}"
    DESTINATION "${config_install_dir}"
)

# Config
#   * <prefix>/lib/cmake/Foo/FooTargets.cmake
install(
    EXPORT "${TARGETS_EXPORT_NAME}"
    NAMESPACE "${namespace}"
    DESTINATION "${config_install_dir}"
)
