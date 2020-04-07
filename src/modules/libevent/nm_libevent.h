#ifndef _NM_LIBEVENT_H_
#define _NM_LIBEVENT_H_


#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct event_base;

void nm_libevent_init(struct np_platform* pl, struct event_base* eventBase);
void nm_libevent_deinit(struct np_platform* pl);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
