set(src

  nm_iam.c
  nm_iam_role.c
  nm_iam_user.c
  nm_iam_to_json.c
  nm_iam_from_json.c
  nm_iam_auth_handler.c
  nm_iam_pake_handler.c
  nm_iam_configuration.c
  nm_iam_state.c
  nm_iam_serializer.c
  nm_iam_pairing.c
  nm_iam_internal.c
  coap_handler/nm_iam_coap_handler.c
  coap_handler/nm_iam_pairing_get.c
  coap_handler/nm_iam_pairing_password_open.c
  coap_handler/nm_iam_pairing_password_invite.c
  coap_handler/nm_iam_pairing_local_open.c
  coap_handler/nm_iam_pairing_local_initial.c
  coap_handler/nm_iam_get_notification_categories.c
  coap_handler/nm_iam_send_fcm_test.c
  coap_handler/nm_iam_list_users.c
  coap_handler/nm_iam_get_me.c
  coap_handler/nm_iam_get_user.c
  coap_handler/nm_iam_create_user.c
  coap_handler/nm_iam_delete_user.c
  coap_handler/nm_iam_list_roles.c
  coap_handler/nm_iam_set_user_role.c
  coap_handler/nm_iam_set_user_name.c
  coap_handler/nm_iam_set_user_display_name.c
  coap_handler/nm_iam_set_user_fingerprint.c
  coap_handler/nm_iam_set_user_sct.c
  coap_handler/nm_iam_set_user_password.c
  coap_handler/nm_iam_set_user_fcm.c
  coap_handler/nm_iam_set_user_notification_categories.c
  coap_handler/nm_iam_settings_get.c
  coap_handler/nm_iam_settings_set.c
  policies/nm_condition.c
  policies/nm_statement.c
  policies/nm_policy.c
  policies/nm_policies_from_json.c
  policies/nm_policies_to_json.c
  )

add_library(nm_iam ${src})
target_link_libraries(nm_iam nabto_device_static 3rdparty_cjson 3rdparty_tinycbor nn)
