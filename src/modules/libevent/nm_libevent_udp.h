#ifndef _NM_LIBEVENT_UDP_H_
#define _NM_LIBEVENT_UDP_H_

struct np_platform;
struct event_base;

struct nm_libevent_context;

void nm_libevent_udp_init(struct np_platform* pl, struct nm_libevent_context* ctx);
void nm_libevent_udp_deinit(struct np_platform* pl);

#endif
