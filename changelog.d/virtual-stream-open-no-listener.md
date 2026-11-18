### Bug fixes
 * Fixed a use-after-free and double free when
   `nabto_device_virtual_stream_open()` was called with a port that had no
   stream listener. The open future now resolves with
   `NABTO_DEVICE_EC_STOPPED`, and the virtual stream can be freed safely.
 * The `nabto_device_virtual_stream_open()` future now resolves with
   `NABTO_DEVICE_EC_STOPPED` when the application frees the new stream without
   accepting it, as documented. Previously it never resolved.
