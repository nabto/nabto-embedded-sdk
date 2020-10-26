set(src
  nm_iam.c
  nm_iam_role.c
  nm_iam_user.c
  nm_iam_to_json.c
  nm_iam_from_json.c
  nm_iam_list_users.c
  nm_iam_pairing_get.c
  nm_iam_pairing_password.c
  nm_iam_pairing_local.c
  nm_iam_auth_handler.c
  nm_iam_pake_handler.c
  nm_iam_coap_handler.c
  nm_iam_is_paired.c
  nm_iam_get_me.c
  nm_iam_get_user.c
  nm_iam_create_user.c
  nm_iam_delete_user.c
  nm_iam_list_roles.c
  nm_iam_set_user_role.c
  nm_iam_client_settings.c
  )

add_library(nm_iam ${src})
target_link_libraries(nm_iam nm_policies 3rdparty_cjson 3rdparty_tinycbor nn)
