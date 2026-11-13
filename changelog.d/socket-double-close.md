### Bug fixes
 * When binding a UDP socket failed, for example because the port was in use,
   the select_unix module and the mDNS sockets of the select_unix and
   libevent modules closed the socket but kept its descriptor number. Freeing
   the socket closed that number again, and if it had been reused in the
   meantime, it closed an unrelated file or socket in the process.
