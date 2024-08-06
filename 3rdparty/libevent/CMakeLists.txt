if (NABTO_DEVICE_LIBEVENT_PROVIDER STREQUAL "module")
  set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable libevent openssl")
  set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "disable libevent benchmarks")
  set(EVENT__DISABLE_TESTS ON CACHE BOOL "disable libevent tests")
  set(EVENT__DISABLE_REGRESS ON CACHE BOOL "disable libevent regression tests")
  set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "disable libevent samples")
  set(EVENT__DISABLE_MBEDTLS ON CACHE BOOL "disable libevent mbedtls")
  set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable libevent openssl")
  set(EVENT__LIBRARY_TYPE STATIC CACHE STRING "libevent library type")

  set(libevent_patch_command git apply ${CMAKE_CURRENT_LIST_DIR}/patches/libevent.patch || exit 0)

  FetchContent_Declare(
    Libevent
    GIT_REPOSITORY https://github.com/libevent/libevent.git
    GIT_TAG        7f23b5b5aa61f5496627c2651fd6d8185f34ffde
    PATCH_COMMAND ${libevent_patch_command}
    OVERRIDE_FIND_PACKAGE
  )
  FetchContent_MakeAvailable(Libevent)
endif()
