set(src
  tinycbor/src/cborencoder.c
  tinycbor/src/cborparser.c
  tinycbor/src/cborparser_dup_string.c
  tinycbor/src/cbortojson.c
  tinycbor/src/cborvalidation.c
  )

add_library(3rdparty_tinycbor ${src})
target_include_directories(3rdparty_tinycbor PUBLIC tinycbor/src)
