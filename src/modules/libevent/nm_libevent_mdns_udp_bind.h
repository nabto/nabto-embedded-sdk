#ifndef NM_LIBEVENT_MDNS_UDP_BIND_H_
#define NM_LIBEVENT_MDNS_UDP_BIND_H_

#include <modules/mdns/nm_mdns_udp_bind.h>

struct nm_libevent_context;

struct nm_mdns_udp_bind nm_libevent_mdns_udp_bind_get_impl(struct nm_libevent_context* libeventContext);

#endif
