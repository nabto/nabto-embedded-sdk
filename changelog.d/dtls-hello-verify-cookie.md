### Breaking changes
 * `np_dtls_srv_module.create_connection` takes a client id which the DTLS
   cookie is bound to, and the module has a new `verify_client_hello`
   function. Only platform integrations with their own DTLS server module are
   affected; `verify_client_hello` may be set to `NULL`.

### Security
 * The mbedtls DTLS server now does the DTLS HelloVerifyRequest cookie
   exchange. Previously a ClientHello from a spoofed address was answered with
   the full ServerHello flight and its retransmissions, which made the device
   usable as a DDoS reflector with roughly 30-40x amplification, and every
   such packet allocated a client connection. A ClientHello without a valid
   cookie is now answered statelessly with a HelloVerifyRequest smaller than
   the request, and a connection is only allocated once the client has echoed
   the cookie from the same address.
 * * The wolfSSL DTLS module does not implement the stateless check yet.
