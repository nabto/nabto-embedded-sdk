### Bug fixes
 * Fixed a NULL dereference in `nabto_device_get_attach_certificate_expiration()`
   when the device was not attached, e.g. before the first attach or while
   reattaching. It now returns `NABTO_DEVICE_EC_NOT_ATTACHED`, as documented.
