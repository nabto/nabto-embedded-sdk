### Security
 * `nabto_device_set_server_url()`, `nabto_device_set_product_id()`,
   `nabto_device_set_device_id()`, `nabto_device_set_app_name()` and
   `nabto_device_set_app_version()` now return
   `NABTO_DEVICE_EC_INVALID_STATE` after `nabto_device_start()`. They used to
   free the old string while the device still used it for attaching to the
   basestation, which was a use-after-free on the next attach. The
   documentation already required these to be called before
   `nabto_device_start()`.
