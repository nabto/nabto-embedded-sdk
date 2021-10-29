include("${CMAKE_CURRENT_SOURCE_DIR}/../../cmake-scripts/nabto_version.cmake")
cmake_policy(SET CMP0007 NEW)

nabto_version(version_out version_error)

if (NOT version_out)
  if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c)

    message(FATAL_ERROR "No file ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c exists and it cannot be auto generated. ${version_error}")
  endif()
else()

  set(VERSION "#include \"nc_version.h\"\n
static const char* nc_version_str = \"${version_out}\"\n;
const char* nc_version() { return nc_version_str; }\n")

  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c)
    file(READ ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c VERSION_)
  else()
    set(VERSION_ "")
  endif()

  if (NOT "${VERSION}" STREQUAL "${VERSION_}")
    file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/nc_version.c "${VERSION}")
  endif()
endif()
