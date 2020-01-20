#ifndef _NM_UNIX_MDNS_H_
#define _NM_UNIX_MDNS_H_

#include <stdbool.h>

/**
 * init functions common for both epoll and select on unix
 */

bool nm_unix_init_mdns_ipv6_socket(int sock);
bool nm_unix_init_mdns_ipv4_socket(int sock);

void nm_unix_mdns_update_ipv4_socket_registration(int sock);
void nm_unix_mdns_update_ipv6_socket_registration(int sock);


#endif
