### Security
 * The DTLS modules now keep datagrams 16 bytes smaller than a communication
   buffer. Datagrams on client connections get a 16 byte connection id header
   inserted in front of them in the same buffer, and a datagram filling the
   whole buffer was written up to 16 bytes past its end. With the default
   1500 byte communication buffer no datagram was large enough to trigger
   this, but builds with a smaller `NABTO_COMMUNICATION_BUFFER_LENGTH` could
   be affected during the DTLS handshake. CoAP packets are now limited to 16
   bytes less than before, to keep room for the header.
