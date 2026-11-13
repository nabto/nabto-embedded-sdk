### Bug fixes
 * `nabto_device_virtual_stream_read_all` returned without releasing the device
   mutex when a read was already in progress on the stream. The future was
   resolved with `NABTO_DEVICE_EC_OPERATION_IN_PROGRESS`, but every later call
   into the device, and the device's own event thread, then blocked forever.
