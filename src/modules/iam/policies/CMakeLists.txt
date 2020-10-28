set(src
  nm_condition.c
  nm_statement.c
  nm_policy.c
  nm_policies_from_json.c
  nm_policies_to_json.c
  )

add_library(nm_policies ${src})
target_link_libraries(nm_policies 3rdparty_cjson nn)
