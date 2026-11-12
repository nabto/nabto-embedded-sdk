### Bug fixes
 * `nm_iam_add_user_fingerprint()` no longer crashes when the fingerprint name
   is `NULL`, which the documentation allows.
 * `nabto_device_authorization_request_get_attribute_name()` and
   `nabto_device_authorization_request_get_attribute_value()` return `NULL`
   for an index out of range instead of crashing.
 * `nabto_device_connection_get_password_authentication_username()` returns
   `NABTO_DEVICE_EC_INVALID_STATE` instead of crashing when called on a
   connection which has not attempted password authentication.
