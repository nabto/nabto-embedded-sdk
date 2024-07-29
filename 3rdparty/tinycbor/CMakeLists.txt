set(src
  tinycbor_src/src/cborencoder.c
  tinycbor_src/src/cborparser.c
  tinycbor_src/src/cborparser_dup_string.c
  tinycbor_src/src/cbortojson.c
  tinycbor_src/src/cborvalidation.c
  )

add_library(tinycbor ${src})
add_library(TinyCBOR::tinycbor ALIAS tinycbor)
target_include_directories(tinycbor PRIVATE tinycbor_src/include/tinycbor)
target_include_directories(tinycbor PUBLIC tinycbor_src/include)

install(TARGETS tinycbor)
install(FILES tinycbor_src/include/tinycbor/cbor.h tinycbor_src/include/tinycbor/cborjson.h tinycbor_src/include/tinycbor/tinycbor-version.h DESTINATION include/tinycbor)
