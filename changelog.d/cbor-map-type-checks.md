### Security
 * A password authentication request (`POST /p2p/pwd-auth/1`) whose CBOR
   payload is not a map is now rejected with 4.00 Bad Request. It was read as a
   map anyway, which aborted the device in builds with assertions enabled, and
   was undefined behaviour otherwise. Any client could send it before
   authenticating.
 * An ICE servers response from the basestation with an element which is not a
   map is now rejected as a bad response, instead of being read as a map.
