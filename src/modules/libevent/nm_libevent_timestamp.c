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


// TODO add data to platform.
static struct event_base* eventBase;

static bool ts_passed_or_now(np_timestamp* ts);
static bool ts_less_or_equal(np_timestamp* t1, np_timestamp* t2);
static void ts_set_future_timestamp(np_timestamp* ts, uint32_t ms);
static void ts_now(np_timestamp* ts);
static uint32_t ts_now_ms();

void nm_libevent_timestamp_init(struct event_base* eb, struct np_platform* pl)
{
    eventBase = eb;
    pl->ts.passed_or_now        = &ts_passed_or_now;
    pl->ts.less_or_equal        = &ts_less_or_equal;
    pl->ts.set_future_timestamp = &ts_set_future_timestamp;
    pl->ts.now                  = &ts_now;
    pl->ts.now_ms               = &ts_now_ms;
}

bool ts_passed_or_now(np_timestamp* ts)
{
    np_timestamp now;
    ts_now(&now);
    return (now >= *ts);
}

bool ts_less_or_equal(np_timestamp* t1, np_timestamp* t2)
{
    return (*t1 <= *t2);
}

void ts_set_future_timestamp(np_timestamp* ts, uint32_t ms)
{
    ts_now(ts);
    *ts = *ts + ms;
}

void ts_now(np_timestamp* ts)
{
    struct timeval tv;
    event_base_gettimeofday_cached(eventBase, &tv);

    *ts = (((uint64_t)tv.tv_sec)*1000) + (((uint64_t)tv.tv_usec)/1000);
}

uint32_t ts_now_ms()
{
    struct timeval tv;
    event_base_gettimeofday_cached(eventBase, &tv);

    return ((((uint64_t)tv.tv_sec)*1000) + (((uint64_t)tv.tv_usec)/1000));
}
