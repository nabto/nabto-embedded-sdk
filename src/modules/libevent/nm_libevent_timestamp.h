#ifndef _NM_LIBEVENT_TIMESTAMP_H_
#define _NM_LIBEVENT_TIMESTAMP_H_

struct np_platform;
struct event_base;

void nm_libevent_timestamp_init(struct event_base* eventBase, struct np_platform* pl);

#endif
