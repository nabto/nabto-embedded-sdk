#ifndef _NM_LIBEVENT_H_
#define _NM_LIBEVENT_H_

#include <platform/np_communication_buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct event_base;

struct nm_libevent_context {
    struct event_base* eventBase;
    struct np_platform* pl;
    struct np_communication_buffer* recvBuffer;
};

void nm_libevent_global_init();
void nm_libevent_global_deinit();
void nm_libevent_init(struct np_platform* pl, struct nm_libevent_context* ctx, struct event_base* eventBase);
void nm_libevent_deinit(struct nm_libevent_context* ctx);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
