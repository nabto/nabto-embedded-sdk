### Bug fixes
 * Fixed a use-after-free when `nabto_device_stream_close()` was called while
   an earlier close of the same stream was outstanding. The second close now
   resolves with `NABTO_DEVICE_EC_OPERATION_IN_PROGRESS`, as documented, and
   the first close is not affected.
