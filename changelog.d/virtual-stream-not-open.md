### Security
 * Fixed a NULL dereference when `nabto_device_virtual_stream_read_all()`,
   `_read_some()`, `_write()`, `_close()` or `_abort()` was called on a virtual
   stream which had not been opened, or whose open failed, e.g. because the
   limit set with `nabto_device_limit_streams()` was reached. These now
   resolve the future with `NABTO_DEVICE_EC_INVALID_STATE`, and abort does
   nothing.
 * When a virtual stream open resolved with `NABTO_DEVICE_EC_STOPPED`, e.g.
   because there was no stream listener, a later read on the stream was never
   resolved. Operations on such a stream, and on a stream whose open future
   has not resolved yet, now resolve with `NABTO_DEVICE_EC_INVALID_STATE`, and
   the stream can be opened again.
 * `nabto_device_virtual_stream_open()` on a stream which is open or being
   opened now resolves with `NABTO_DEVICE_EC_INVALID_STATE`. It used to
   replace the first stream, which was leaked.
