#include "nm_libevent_timestamp.h"

#include <platform/np_platform.h>
#include <platform/np_timestamp.h>

#include <event2/event.h>

#if defined(HAVE_SYS_TIME_H)
#include <sys/time.h>
#endif

#if defined(HAVE_WINSOCK2_H)
#include <winsock2.h>
#endif

static uint32_t ts_now_ms(struct np_platform* pl);

void nm_libevent_timestamp_init(struct event_base* eb, struct np_platform* pl)
{
    pl->tsData = eb;
    pl->ts.now_ms               = &ts_now_ms;
}

uint32_t ts_now_ms(struct np_platform* pl)
{
    struct event_base* eventBase = pl->tsData;
    struct timeval tv;
    event_base_gettimeofday_cached(eventBase, &tv);

    return ((((uint64_t)tv.tv_sec)*1000) + (((uint64_t)tv.tv_usec)/1000));
}
