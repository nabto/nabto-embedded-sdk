set(src
  nc_iam.c
  nc_iam_util.c
  nc_iam_cbor.c
  nc_iam_policy.c
  nc_iam_coap.c
  nc_iam_dump.c
  nc_iam_load.c
  )

add_library(nm_iam ${src})
target_link_libraries(nm_iam 3rdparty_tinycbor np_platform nc_core)
