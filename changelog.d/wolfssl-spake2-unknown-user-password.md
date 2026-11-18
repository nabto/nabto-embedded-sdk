### Security
 * wolfSSL builds: when no password was given for a password authentication
   request (`nabto_device_password_authentication_request_set_password()` with
   `NULL`, or a request freed without a password), the device should use a
   random password but used the value 0 instead. A client which knew this could
   complete password authentication for such a username without a password.
   With the IAM module that covers unknown usernames and users without a
   password, and the connection got the role of that user. mbedtls builds were
   not affected.
