find_path(TINYCBOR_INCLUDE_DIRS tinycbor/cbor.h)

find_library(TINYCBOR_LIBRARY tinycbor)

if(NOT TINYCBOR_LIBRARY_FOUND)
  message(INFO "TinyCBOR library not found")
else()
  add_library(TinyCBOR::tinycbor STATIC IMPORTED)
  target_link_libraries(TinyCBOR::tinycbor INTERFACE "${TINYCBOR_LIBRARY}")
  set_target_properties(TinyCBOR::tinycbor PROPERTIES IMPORTED_LOCATION "${TINYCBOR_LIBRARY}")

  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(TinyCBOR DEFAULT_MSG
    TINYCBOR_INCLUDE_DIRS TINYCBOR_LIBRARY)

  mark_as_advanced(TINYCBOR_INCLUDE_DIRS TINYCBOR_LIBRARY)
endif()
