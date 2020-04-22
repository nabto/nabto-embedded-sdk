#ifndef NM_LIBEVENT_GET_LOCAL_IP_H
#define NM_LIBEVENT_GET_LOCAL_IP_H

#include <platform/np_platform.h>

#include <string.h>

size_t nm_libevent_get_local_ip( struct np_ip_address *addrs, size_t addrsSize);

#endif
