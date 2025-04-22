#ifndef NM_LIBEVENT_UDP_H_
#define NM_LIBEVENT_UDP_H_

#include <platform/np_completion_event.h>
#include <platform/np_ip_address.h>

#include <event.h>
#include <event2/util.h>

#include <stdbool.h>

struct nm_libevent_context;

struct received_ctx {
    struct np_completion_event* completionEvent;
};


struct np_udp_socket {
    struct received_ctx recv;
    enum np_ip_address_type type;
    evutil_socket_t sock;
    struct nm_libevent_context* impl;
    bool aborted;
    struct event* event;
};

np_error_code nm_libevent_udp_add_to_libevent(struct np_udp_socket* sock);

evutil_socket_t nm_libevent_udp_create_nonblocking_socket(int domain, int type);

#ifdef __cplusplus
extern "C" {
#endif

void nm_libevent_udp_test_recv_failure(struct np_udp_socket* sock);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
