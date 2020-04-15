#ifndef _NM_LIBEVENT_TCP_H_
#define _NM_LIBEVENT_TCP_H_

struct np_platform;
struct nm_libevent_context;

void nm_libevent_tcp_init(struct np_platform* pl, struct nm_libevent_context* ctx);

#endif
