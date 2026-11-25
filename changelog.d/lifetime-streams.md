### Bug fixes
 * Fixed a use-after-free when `nabto_device_stream_free()` was called while
   an accept, read, write or close operation on the stream was outstanding.
   The futures of such operations are now resolved when the stream is freed,
   typically with `NABTO_DEVICE_EC_ABORTED`.
 * Fixed a use-after-free and double free when
   `nabto_device_virtual_stream_open()` was called with a port that had no
   stream listener. The open future now resolves with
   `NABTO_DEVICE_EC_STOPPED`, and the virtual stream can be freed safely.
 * The `nabto_device_virtual_stream_open()` future now resolves with
   `NABTO_DEVICE_EC_STOPPED` when the application frees the new stream without
   accepting it, as documented. Previously it never resolved.
 * Fixed a use-after-free when `nabto_device_virtual_stream_free()` was called
   while an operation on the virtual stream was outstanding. The futures of
   such operations are resolved with `NABTO_DEVICE_EC_ABORTED`.
 * Freeing a virtual connection now stops the streams on it, instead of
   leaving them with a pointer to the freed connection.
