#include "nm_libevent.h"

#include "nm_libevent_dns.h"
#include "nm_libevent_udp.h"
#include "nm_libevent_tcp.h"
#include "nm_libevent_get_local_ip.h"
#include "nm_libevent_timestamp.h"

#include <platform/np_platform.h>
#include <event2/event.h>
#include <event2/thread.h>

#if defined(HAVE_WINSOCK2_H)
#include <winsock2.h>
#endif

static int useCount = 0;

void nm_libevent_global_init()
{
    if (useCount == 0) {
#ifdef _WIN32
        WSADATA wsa_data;
        WSAStartup(0x0201, &wsa_data);
#endif
        //event_enable_debug_mode();
#if defined(HAVE_PTHREAD_H)
        evthread_use_pthreads();
#elif defined(HAVE_WINDOWS_H)
        evthread_use_windows_threads();
#else
#error "missing thread library"
#endif
    }
    useCount++;
}

void nm_libevent_global_deinit()
{
    useCount--;
    if (useCount == 0) {
        libevent_global_shutdown();
    }
}

void nm_libevent_init(struct nm_libevent_context* ctx, struct event_base* eventBase)
{
    ctx->eventBase = eventBase;

    // TODO
    //nm_libevent_dns_init(pl, ctx->eventBase);
    //nm_libevent_udp_init(pl, ctx);
    //nm_libevent_timestamp_init(eventBase, pl);
    //nm_libevent_tcp_init(pl, ctx);
    //nm_libevent_local_ip_init(pl);

}

void nm_libevent_deinit(struct nm_libevent_context* ctx)
{
    //nm_libevent_dns_deinit(pl);

}



struct np_udp_object nm_libevent_create_udp_object(struct nm_libevent_context* ctx)
{
    struct np_udp_object obj;
    obj.vptr = nm_libevent_udp_functions();
    obj.data = ctx;
    return obj;
}

struct np_tcp_object nm_libevent_create_tcp_object(struct nm_libevent_context* ctx)
{
    struct np_tcp_object obj;
    obj.vptr = nm_libevent_tcp_functions();
    obj.data = ctx;
    return obj;
}

struct np_timestamp_object nm_libevent_create_timestamp_object(struct nm_libevent_context* ctx)
{
    struct np_timestamp_object obj;
    obj.vptr = nm_libevent_timestamp_functions();
    obj.data = ctx;
    return obj;
}

struct np_dns_object nm_libevent_create_dns_object(struct nm_libevent_context* ctx)
{
    struct np_dns_object obj;
    obj.vptr = nm_libevent_dns_functions();
    obj.data = ctx;
    return obj;
}
