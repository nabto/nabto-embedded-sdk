#ifndef _NM_LIBEVENT_UDP_H_
#define _NM_LIBEVENT_UDP_H_

struct np_platform;
struct event_base;

void nm_libevent_udp_init(struct np_platform* pl, struct event_base* eventBase);
void nm_libevent_udp_deinit(struct np_platform* pl);

#endif
