find_path(TINYCBOR_INCLUDE_DIRS tinycbor/cbor.h)

find_library(TINYCBOR_LIBRARY tinycbor)

if(TINYCBOR_LIBRARY-NOTFOUND)
  message(FATAL_ERROR foo)
  message(INFO "TinyCBOR library not found")
elseif(NOT TARGET TinyCBOR::tinycbor)

  add_library(TinyCBOR::tinycbor STATIC IMPORTED)
  target_link_libraries(TinyCBOR::tinycbor INTERFACE "${TINYCBOR_LIBRARY}")
  set_target_properties(TinyCBOR::tinycbor PROPERTIES IMPORTED_LOCATION "${TINYCBOR_LIBRARY}")
  target_include_directories(TinyCBOR::tinycbor INTERFACE "${TINYCBOR_INCLUDE_DIRS}")

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(TinyCBOR DEFAULT_MSG
    TINYCBOR_INCLUDE_DIRS TINYCBOR_LIBRARY)

  mark_as_advanced(TINYCBOR_INCLUDE_DIRS TINYCBOR_LIBRARY)
endif()
