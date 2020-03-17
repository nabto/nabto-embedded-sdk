set(src
  nm_iam_role.c
  nm_iam_to_json.c
  nm_iam_from_json.c
  )

add_library(nm_iam ${src})
target_link_libraries(nm_iam nm_policies 3rdparty_cjson)
