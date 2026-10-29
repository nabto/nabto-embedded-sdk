### Security
 * Fixed `nabto_device_connection_get_device_fingerprint()` on a virtual
   connection returning a string which was not NUL terminated. Using it as a C
   string read past the end of the allocation. It also returns
   `NABTO_DEVICE_EC_OUT_OF_MEMORY` now if the allocation fails.
