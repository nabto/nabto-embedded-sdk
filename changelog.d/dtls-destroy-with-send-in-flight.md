### Security
 * A client connection which was closed while the device was still sending a
   DTLS packet on it was never freed. A remote peer could trigger this without
   authenticating, e.g. with a DTLS ClientHello the device rejects, and leak
   one connection per packet until the device ran out of memory. Such a
   connection is now freed once the packet is done, and the DTLS layer no
   longer calls into a connection which has already been closed.
