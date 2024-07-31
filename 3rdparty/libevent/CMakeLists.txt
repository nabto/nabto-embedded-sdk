find_package(Libevent COMPONENTS core extra pthreads)

if (Libevent_FOUND)
else ()


  set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable libevent openssl")
  set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "disable libevent benchmarks")
  set(EVENT__DISABLE_TESTS ON CACHE BOOL "disable libevent tests")
  set(EVENT__DISABLE_REGRESS ON CACHE BOOL "disable libevent regression tests")
  set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "disable libevent samples")
  set(EVENT__DISABLE_MBEDTLS ON CACHE BOOL "disable libevent mbedtls")
  set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable libevent openssl")
  set(EVENT__LIBRARY_TYPE STATIC CACHE STRING "libevent library type")

  FetchContent_Declare(
    Libevent
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libevent
    FIND_PACKAGE_ARGS
  )
  FetchContent_MakeAvailable(Libevent)

  # include_directories(libevent/include)

  # add_subdirectory(libevent)

  if (NOT TARGET libevent::core)
    add_library(libevent::core ALIAS event_core)
  endif()

  if (NOT TARGET libevent::extra)
    add_library(libevent::extra ALIAS event_extra)
  endif()

  if (NOT WIN32)
    if (NOT TARGET libevent::pthreads)
      add_library(libevent::pthreads ALIAS event_pthreads)
    endif()
  endif()
endif()
