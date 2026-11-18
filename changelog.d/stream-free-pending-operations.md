### Bug fixes
 * Fixed a use-after-free when `nabto_device_stream_free()` was called while
   an accept, read, write or close operation on the stream was outstanding.
   The futures of such operations are now resolved when the stream is freed,
   typically with `NABTO_DEVICE_EC_ABORTED`.
