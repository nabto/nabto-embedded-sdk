### Bug fixes
 * With the wolfSSL DTLS module, a failure to sign the device certificate was
   not detected. The negative error code was then used as the certificate
   length when converting it to PEM, which read past the certificate buffer.
