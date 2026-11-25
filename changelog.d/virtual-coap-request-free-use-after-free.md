### Security
 * Fixed a use-after-free when a virtual CoAP request was freed with
   `nabto_device_virtual_coap_request_free()` before the device application
   had answered it. The later response, or closing the virtual connection,
   wrote into the freed request. Freeing a virtual CoAP request which has not
   been answered now resolves its future with `NABTO_DEVICE_EC_STOPPED`.
