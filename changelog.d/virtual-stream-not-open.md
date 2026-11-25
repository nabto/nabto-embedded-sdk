### Security
 * Fixed a NULL dereference when `nabto_device_virtual_stream_read_all()`,
   `_read_some()`, `_write()`, `_close()` or `_abort()` was called on a virtual
   stream which had not been opened, or whose open failed, e.g. because the
   limit set with `nabto_device_limit_streams()` was reached. These now
   resolve the future with `NABTO_DEVICE_EC_INVALID_STATE`, and abort does
   nothing.
 * `nabto_device_virtual_stream_open()` on a stream which has already been
   opened now resolves with `NABTO_DEVICE_EC_INVALID_STATE`. It used to
   replace the first stream, which was leaked.
