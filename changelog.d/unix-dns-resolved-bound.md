### Security
 * Fixed a buffer overflow in the unix DNS resolver (`nm_unix_dns`) when a
   hostname resolved to more addresses than the caller's array could hold. The
   bound check used a counter which was only updated after the loop, so every
   address was written. The core passes room for 4 addresses per family, so a
   DNS answer with 5 or more A or AAAA records for the basestation or STUN
   hostname overflowed it. The resolver is used by the select_unix platform
   integration example and the platform integration steps; the libevent
   resolver was not affected.
