
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
      -DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=ON
      -DCMAKE_INSTALL_PREFIX:PATH=${CMAKE_CURRENT_BINARY_DIR}/libevent
)


ExternalProject_Add(nabto-embedded-sdk
  PREFIX nabto-embedded-sdk
  SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.."
  BUILD_ALWAYS 1
  CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
        -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/nabto-embedded-sdk
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
  CMAKE_CACHE_ARGS
        -DLibevent_DIR:PATH=${CMAKE_CURRENT_BINARY_DIR}/libevent/lib/cmake/libevent

  DEPENDS libevent
  )
