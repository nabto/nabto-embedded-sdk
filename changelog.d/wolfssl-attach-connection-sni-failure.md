### Bug fixes
 * wolfSSL builds: if setting the SNI hostname of the DTLS connection to the
   basestation failed, e.g. when out of memory, the freed connection was kept
   by the attacher and freed again later, leading to a use after free and a
   double free.
