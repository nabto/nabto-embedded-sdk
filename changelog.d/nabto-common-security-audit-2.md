### Security
 * Updated nabto-common with a second round of security audit fixes. A
   connected client could previously make the device allocate stream receive
   buffers without bound by sending data the application did not read, bypass
   stream replay protection by sending a syn|ack to the device, and crash the
   device by removing a CoAP resource in the middle of a Block1 transfer or by
   sending requests to a route with a `{parameter}` segment while the device
   was out of memory.

### Bug fixes
 * Fixed a stream which stalled for good when the ack reopening a closed
   receive window was lost. The sender now probes a closed window.
 * Fixed CoAP observe registrations being accepted for a request whose
   connection was already closed, and the CoAP client sending a queued ACK or
   RST on a connection after it was removed.
