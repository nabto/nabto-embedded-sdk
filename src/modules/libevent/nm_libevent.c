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
}

struct np_udp nm_libevent_create_udp(struct nm_libevent_context* ctx)
{
    struct np_udp obj;
    obj.vptr = nm_libevent_udp_functions();
    obj.data = ctx;
    return obj;
}

struct np_tcp nm_libevent_create_tcp(struct nm_libevent_context* ctx)
{
    struct np_tcp obj;
    obj.vptr = nm_libevent_tcp_functions();
    obj.data = ctx;
    return obj;
}

struct np_timestamp nm_libevent_create_timestamp(struct nm_libevent_context* ctx)
{
    struct np_timestamp obj;
    obj.vptr = nm_libevent_timestamp_functions();
    obj.data = ctx;
    return obj;
}

struct np_dns nm_libevent_create_dns(struct nm_libevent_context* ctx)
{
    struct np_dns obj;
    obj.vptr = nm_libevent_dns_functions();
    obj.data = ctx;
    return obj;
}
