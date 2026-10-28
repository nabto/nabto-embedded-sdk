### Security
 * Fixed a use-after-free in `nabto_device_fcm_stop()` and
   `nabto_device_service_invocation_stop()` when called after the request had
   completed.
 * `nabto_device_fcm_notification_free()` and
   `nabto_device_service_invocation_free()` now abort a request which is still
   in progress, and resolve its future with `NABTO_DEVICE_EC_STOPPED`.
   Previously a late response from the basestation was written into the freed
   object.
