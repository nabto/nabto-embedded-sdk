#include <api/nabto_platform.h>

#include <modules/libevent/nm_libevent.h>
#include <modules/timestamp/unix/nm_unix_timestamp.h>
#include <modules/dtls/nm_random.h>
#include <modules/mdns/nm_mdns.h>
#include <modules/dtls/nm_dtls_cli.h>
#include <modules/dtls/nm_dtls_srv.h>
#include <modules/logging/api/nm_api_logging.h>

#include <event.h>
#include <event2/event.h>
#include <event2/thread.h>

struct event_base* eventBase;
struct nm_libevent_context libeventContext;

void nabto_device_init_platform(struct np_platform* pl)
{
    np_platform_init(pl);
    nm_api_log_init();
#if defined(HAVE_PTHREAD_H)
    evthread_use_pthreads();
#elif defined(HAVE_WINDOWS_H)
    evtgread_use_windows_threads();
#else
    #error "missing thread library"
#endif
    eventBase = event_base_new();
}

void nabto_device_deinit_platform(struct np_platform* pl)
{
    event_base_free(eventBase);
    np_platform_deinit(pl);
}

np_error_code nabto_device_init_platform_modules(struct np_platform* pl)
{
    np_communication_buffer_init(pl);
    nm_libevent_init(pl, &libeventContext, eventBase);

    nm_unix_ts_init(pl);
    nm_dtls_cli_init(pl);
    nm_dtls_srv_init(pl);
    nm_mdns_init(pl);
    nm_random_init(pl);
    return NABTO_EC_OK;
}

void nabto_device_deinit_platform_modules(struct np_platform* pl)
{
    nm_libevent_deinit(&libeventContext);
}

int nabto_device_platform_inf_wait()
{
    event_base_loop(eventBase, EVLOOP_NO_EXIT_ON_EMPTY);
    return 0;
}

void nabto_device_platform_read(int nfds)
{
    // read is handled in inf wat
}

void nabto_device_platform_close(struct np_platform* pl)
{
    // TODO
}

void nabto_device_platform_signal(struct np_platform* pl)
{
    event_base_loopbreak(eventBase);
}

bool nabto_device_platform_finished()
{
    return true;
}
