### Bug fixes
 * `nabto_device_stream_init_listener` and
   `nabto_device_stream_init_listener_ephemeral` returned with the device
   mutex locked when they failed, for example when the stream port was
   already in use, so the device hung on the next call. When the port was in
   use the listener was also left pointing at freed memory. Both now unlock
   on every path and leave the listener unused on failure.
