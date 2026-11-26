### Bug fixes
 * `nabto_device_virtual_stream_read_all()` and `_read_some()` on a virtual
   stream which has been aborted now resolve with `NABTO_DEVICE_EC_ABORTED`.
   The read used to be stored and never resolved, so the future hung, the
   stream was leaked and `nabto_device_stop()` waited for its drain timeout.
