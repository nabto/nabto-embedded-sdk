### Security
 * Fixed a memory leak in the wolfSSL DTLS client. Each lookup of the peer's
   fingerprint leaked a copy of its certificate. In builds with
   `NABTO_DEVICE_DTLS_CLIENT_ONLY`, client connections use the DTLS client, so
   a connected client could make the device leak memory with every request
   which checks its fingerprint.
