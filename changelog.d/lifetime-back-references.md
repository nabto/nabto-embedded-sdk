### Security
 * A connection authorized with `nm_iam_authorize_connection` no longer keeps
   a pointer to the user. Deleting the user, or loading a new state with
   `nm_iam_load_state`, freed the user while the connection was still open,
   after which access checks and `GET /iam/me` read freed memory and could
   send it to the client. The connection is now authorized as the username,
   which is looked up each time it is used: if the user is deleted, the
   connection is treated as unpaired.
 * * `struct nm_iam_authorized_connection` now holds `char* username` instead
   of `struct nm_iam_user* user`.

### Bug fixes
 * Stopping an authorization request listener now detaches it from the
   device. Previously the device kept using the listener after it was stopped
   and freed, so the next authorization request accessed freed memory, and
   `nabto_device_authorization_request_init_listener` returned
   `NABTO_DEVICE_EC_IN_USE` for any new listener.
 * `nabto_device_listener_free()` stops a listener which has not been
   stopped, so the device does not keep using a freed listener.
