### Security
 * Fixed an out-of-bounds read and write in
   `nabto_device_virtual_coap_request_new()` when the path was an empty
   string. The byte before the path buffer was read and could be cleared.
