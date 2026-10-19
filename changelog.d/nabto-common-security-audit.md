### Security
 * Updated nabto-common with the fixes from its security audit. A connected
   client could previously read device heap memory or crash the device through
   a CoAP Block2 request, exhaust device memory with a single stream packet, a
   long CoAP Block1 request or many CoAP observers, and a single mDNS packet
   could hang or crash the device. STUN responses are now checked against the
   transaction id of the request they answer.
 * * The CoAP request body size and the number of CoAP observers can now be
     limited, but nabto-common defaults both to unlimited; the SDK does not set
     them yet.

### Bug fixes
 * Fixed a number of CoAP block transfer, retransmission and memory leak
   issues, and stream segment size negotiation and congestion window
   accounting, found in the same audit.
