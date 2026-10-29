### Security
 * Fixed NULL pointer dereferences when an allocation failed while handling a
   CoAP request, resolving a DNS host name, requesting ICE servers, or sending
   a CoAP error response on a virtual connection. A CoAP request which cannot
   be allocated is now answered with 5.00, and DNS and ICE server requests fail
   with `OUT_OF_MEMORY`.
