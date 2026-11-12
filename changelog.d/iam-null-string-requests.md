### Security
 * Fixed a crash when a client sent `null` as an item in the notification
   categories of `PUT /iam/users/{user}/notification-categories`. The payload
   was decoded before the access check, so any connected client could crash
   the device. The access check is now done before the payload is decoded and
   `null` items are rejected with 400.
 * Fixed a crash when a client with `IAM:CreateUser` sent `null` as the
   `Username` to `POST /iam/users`. It is now rejected with 400.
