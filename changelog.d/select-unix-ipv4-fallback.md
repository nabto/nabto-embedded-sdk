### Bug fixes
 * The select_unix network module never fell back to an IPv4 UDP socket when
   IPv6 socket creation failed. It checked the old socket field, which is
   still invalid at that point, instead of the newly created IPv4 socket, so
   UDP socket creation failed and the IPv4 socket was leaked. When setting
   `IPV6_V6ONLY` failed, the new socket was also leaked instead of closed.
