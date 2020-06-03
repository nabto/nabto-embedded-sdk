#ifndef _NM_LIBEVENT_UDP_H_
#define _NM_LIBEVENT_UDP_H_

struct event_base;

struct nm_libevent_context;

const struct np_udp_functions* nm_libevent_udp_functions();

#endif
