### Bug fixes
 * If `nabto_device_virtual_coap_request_set_payload()` or
   `nabto_device_service_invocation_set_message()` failed to allocate memory
   after a previous successful call, the old length was kept with a missing
   buffer, and executing the request read from a NULL pointer. A failed call
   now leaves the request without a payload. The virtual CoAP request also no
   longer leaks the previous payload when the payload is set twice.
