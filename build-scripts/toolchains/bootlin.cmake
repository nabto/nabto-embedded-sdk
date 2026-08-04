# Generic CMake cross toolchain for Bootlin glibc toolchains.
#
# Driven entirely by environment variables set by build-scripts/linux.sh.
# Environment (not -D cache) variables are used on purpose: vcpkg re-invokes
# this file via VCPKG_CHAINLOAD_TOOLCHAIN_FILE in fresh CMake processes when
# building each dependency, and only the environment survives across those
# sub-processes.
set(CMAKE_SYSTEM_NAME Linux)
if("$ENV{BOOTLIN_TOOLCHAIN_ROOT}" STREQUAL "" OR "$ENV{BOOTLIN_TOOLCHAIN_PREFIX}" STREQUAL "" OR "$ENV{BOOTLIN_SYSROOT}" STREQUAL "" OR "$ENV{BOOTLIN_SYSTEM_PROCESSOR}" STREQUAL "")
  message(FATAL_ERROR "Bootlin toolchain environment not set (BOOTLIN_*). Run build-scripts/linux.sh to configure these variables.")
endif()
set(CMAKE_SYSTEM_PROCESSOR $ENV{BOOTLIN_SYSTEM_PROCESSOR})

set(_tc     $ENV{BOOTLIN_TOOLCHAIN_ROOT})
set(_prefix $ENV{BOOTLIN_TOOLCHAIN_PREFIX})   # e.g. arm-buildroot-linux-gnueabihf-

set(CMAKE_C_COMPILER   ${_tc}/bin/${_prefix}gcc)
set(CMAKE_CXX_COMPILER ${_tc}/bin/${_prefix}g++)
set(CMAKE_AR     ${_tc}/bin/${_prefix}ar     CACHE FILEPATH "")
set(CMAKE_RANLIB ${_tc}/bin/${_prefix}ranlib CACHE FILEPATH "")
set(CMAKE_STRIP  ${_tc}/bin/${_prefix}strip  CACHE FILEPATH "")

set(CMAKE_SYSROOT $ENV{BOOTLIN_SYSROOT})

# Chainloading this file replaces vcpkg's own scripts/toolchains/linux.cmake,
# which is where position independent code is normally enabled. Without it the
# static vcpkg libraries cannot be linked into the shared libraries this project
# builds (libnabto_device.so, libnabto_device_select_unix.so).
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
