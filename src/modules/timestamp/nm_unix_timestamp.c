#include "nm_unix_timestamp.h"
#include <platform/np_logging.h>

#include <time.h>

void nm_unix_ts_init(struct np_platform* pl)
{
    pl->ts.passed_or_now        = &nm_unix_ts_passed_or_now;
    pl->ts.less_or_equal        = &nm_unix_ts_less_or_equal;
    pl->ts.set_future_timestamp = &nm_unix_ts_set_future_timestamp;
    pl->ts.now                  = &nm_unix_ts_now;
    pl->ts.difference           = &nm_unix_ts_difference;
    pl->ts.now_ms               = &nm_unix_ts_now_ms;
}

bool nm_unix_ts_passed_or_now(np_timestamp* ts)
{
    np_timestamp now;
    nm_unix_ts_now(&now);
    return (now >= *ts);
}

bool nm_unix_ts_less_or_equal(np_timestamp* t1, np_timestamp* t2)
{
    return (*t1 <= *t2);
}

void nm_unix_ts_set_future_timestamp(np_timestamp* ts, uint32_t ms)
{
    nm_unix_ts_now(ts);
    *ts = *ts + ms;
}

void nm_unix_ts_now(np_timestamp* ts)
{
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    *ts = (spec.tv_sec * 1000) + (spec.tv_nsec / 1000000);
}

uint32_t nm_unix_ts_difference(np_timestamp* t1, np_timestamp* t2)
{
    if(*t1<*t2) {
        return 0;
    } else {
        return *t1-*t2;
    }
}

uint32_t nm_unix_ts_now_ms()
{
    struct timespec spec;
    clock_gettime(CLOCK_REALTIME, &spec);
    return ((spec.tv_sec * 1000) + (spec.tv_nsec / 1000000));
}
