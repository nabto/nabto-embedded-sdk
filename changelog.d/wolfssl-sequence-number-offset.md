### Bug fixes
 * With wolfSSL, the DTLS sequence number given to the connection was read one
   byte too late in the record header, so it held the low epoch byte, the
   sequence number and the first byte of the record length instead of the epoch
   and sequence number. It now matches the value mbedtls reports. The value
   decides which channel a client connection switches to.
