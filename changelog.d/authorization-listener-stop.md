### Bug fixes
 * Stopping an authorization request listener now detaches it from the
   device. Previously the device kept using the listener after it was stopped
   and freed, so the next authorization request accessed freed memory, and
   `nabto_device_authorization_request_init_listener` returned
   `NABTO_DEVICE_EC_IN_USE` for any new listener.
