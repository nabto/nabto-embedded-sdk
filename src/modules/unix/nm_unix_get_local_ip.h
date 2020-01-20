#ifndef NM_UNIX_GET_LOCAL_IP_H
#define NM_UNIX_GET_LOCAL_IP_H

#include <platform/np_platform.h>

#include <string.h>

size_t nm_unix_get_local_ip( struct np_ip_address *addrs, size_t addrsSize);

#endif
