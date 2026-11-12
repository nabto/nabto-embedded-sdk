### Security
 * Fixed a use-after-free in the IAM `POST /iam/users/{user}/fcm-test` handler
   when sending the test notification failed, for example because the device
   was not attached.
