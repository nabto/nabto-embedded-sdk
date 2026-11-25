### Security
 * Initializing a listener which is already initialized, e.g. calling
   `nabto_device_coap_init_listener()` or `nabto_device_stream_init_listener()`
   twice with the same listener, now fails with
   `NABTO_DEVICE_EC_INVALID_STATE`. The first registration used to stay in
   place, pointing at the listener, so a CoAP request or stream for it was
   delivered to the listener after it had been freed. A stopped listener can
   still be initialized again.
