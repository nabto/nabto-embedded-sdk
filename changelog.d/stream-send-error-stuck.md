### Bug fixes
 * A stream stopped sending packets if a DTLS send was rejected, because the
   connection was closing. The failed packet is now treated as lost, and the
   stream continues, retransmitting it.
