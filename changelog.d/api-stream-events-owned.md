### Bug fixes
 * Streams and virtual streams create their completion events when the stream
   is created instead of on every operation. If the event could not be
   created because the device was out of memory, the operation's future
   never resolved. Now the stream is not created; a new stream is dropped and
   `nabto_device_virtual_stream_new()` returns `NULL`.
