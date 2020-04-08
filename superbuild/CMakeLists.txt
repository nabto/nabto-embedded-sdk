
project(embedded-superbuild)
cmake_minimum_required(VERSION 3.5)

include(ExternalProject)

ExternalProject_Add(libevent
  PREFIX libevent
  URL "https://github.com/libevent/libevent/releases/download/release-2.1.10-stable/libevent-2.1.10-stable.tar.gz"
  CMAKE_CACHE_ARGS
      -DEVENT__DISABLE_OPENSSL:BOOL=ON
      -DEVENT__DISABLE_BENCHMARK:BOOL=ON
      -DEVENT__DISABLE_TESTS:BOOL=ON
      -DEVENT__DISABLE_REGRESS:BOOL=ON
      -DEVENT__DISABLE_SAMPLES:BOOL=ON
      -DEVENT__LIBRARY_TYPE:STRING=STATIC
      -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}/libevent
)


ExternalProject_Add(nabto-embedded-sdk
  PREFIX nabto-embedded-sdk
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.."
  BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/superbuild"
  BUILD_ALWAYS 1
  CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/nabto-embedded-sdk
  CMAKE_CACHE_ARGS
        -Devent_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/libevent

  DEPENDS libevent
  )
