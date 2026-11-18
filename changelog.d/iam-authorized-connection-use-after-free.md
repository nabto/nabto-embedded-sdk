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
