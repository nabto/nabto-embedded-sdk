### Security
 * Initializing a listener which is already initialized, e.g. calling
   `nabto_device_coap_init_listener()` or `nabto_device_stream_init_listener()`
   twice with the same listener, now fails with
   `NABTO_DEVICE_EC_INVALID_STATE`. The first registration used to stay in
   place, pointing at the listener, so a CoAP request or stream for it was
   delivered to the listener after it had been freed. A stopped listener can
   still be initialized again.

### Changed
 * Initializing the same stream, authorization or password authentication
   listener twice with the same registration now returns
   `NABTO_DEVICE_EC_INVALID_STATE`. It used to return
   `NABTO_DEVICE_EC_OPERATION_IN_PROGRESS` (streams) or
   `NABTO_DEVICE_EC_IN_USE`. Initializing a second listener for a
   registration which is in use still returns those codes.
