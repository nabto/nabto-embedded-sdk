set(src
  tinycbor/src/cborencoder.c
  tinycbor/src/cborparser.c
  tinycbor/src/cborparser_dup_string.c
  tinycbor/src/cbortojson.c
  tinycbor/src/cborvalidation.c
  extra/cbor_encode_encoded_cbor.c
  extra/cbor_extra.c
  )

add_library(3rdparty_tinycbor ${src})
if (WIN32)
  target_compile_options(3rdparty_tinycbor INTERFACE /w)
else()
  target_compile_options(3rdparty_tinycbor INTERFACE -w)
endif()
target_include_directories(3rdparty_tinycbor PUBLIC tinycbor/src extra)
