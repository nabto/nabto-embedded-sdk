### Security
 * Fixed a heap buffer overflow in the mbedtls and wolfSSL DTLS modules. A
   DTLS record larger than a communication buffer was copied into one without
   a length check. The DTLS MTU is now set to the communication buffer size,
   records which still do not fit are dropped, and the CoAP client and server
   leave room for the DTLS record overhead (`NP_DTLS_MAX_RECORD_OVERHEAD`).
 * * With wolfSSL the MTU is only set when wolfSSL is built with
     `WOLFSSL_DTLS_MTU` (`--enable-dtls-mtu`), which is recommended.
