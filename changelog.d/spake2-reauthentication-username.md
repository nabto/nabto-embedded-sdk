### Security
 * The username a connection is password authenticated as now only changes
   when a password authentication completes. Previously the first step of a
   new password authentication on the connection replaced it.
   `nabto_device_connection_get_password_authentication_username` returns the
   username of the last successful password authentication, and
   `NABTO_DEVICE_EC_INVALID_STATE` until one has succeeded.
