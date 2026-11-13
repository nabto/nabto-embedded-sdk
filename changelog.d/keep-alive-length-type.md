### Bug fixes
 * The keep-alive request and response length was written through a `size_t*`
   pointing at the 16-bit length of the DTLS send context, overwriting the
   channel id and padding next to it. On big-endian 64-bit targets the length
   ended up as 0, so empty keep-alives were sent and connections and the
   basestation attachment were closed by keep-alive timeout.
