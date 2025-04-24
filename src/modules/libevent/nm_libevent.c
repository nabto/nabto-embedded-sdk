#include "nm_libevent.h"

#include "nm_libevent_get_local_ip.h"

#include <event2/dns.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <platform/np_logging.h>
#include <platform/np_platform.h>

#if defined(HAVE_WINSOCK2_H)
#include <winsock2.h>
#endif

#define LOG NABTO_LOG_MODULE_PLATFORM

static int useCount = 0;

void nm_libevent_global_init(void)
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

void nm_libevent_global_deinit(void)
{
    useCount--;
    if (useCount == 0) {
        libevent_global_shutdown();
    }
}

bool nm_libevent_init(struct nm_libevent_context* ctx, struct event_base* eventBase)
{
    ctx->eventBase = eventBase;
    return true;
}

void nm_libevent_stop(struct nm_libevent_context* ctx)
{
}

void nm_libevent_deinit(struct nm_libevent_context* ctx)
{
}
