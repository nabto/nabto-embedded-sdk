#include "nm_win_timestamp.h"
#include <platform/np_logging.h>

#include <windows.h>

void nm_win_ts_init(struct np_platform* pl)
{
    pl->ts.passed_or_now        = &nm_win_ts_passed_or_now;
    pl->ts.less_or_equal        = &nm_win_ts_less_or_equal;
    pl->ts.set_future_timestamp = &nm_win_ts_set_future_timestamp;
    pl->ts.now                  = &nm_win_ts_now;
    pl->ts.difference           = &nm_win_ts_difference;
    pl->ts.now_ms               = &nm_win_ts_now_ms;
}

bool nm_win_ts_passed_or_now(np_timestamp* ts)
{
    np_timestamp now;
    nm_win_ts_now(&now);
    return (now >= *ts);
}

bool nm_win_ts_less_or_equal(np_timestamp* t1, np_timestamp* t2)
{
    return (*t1 <= *t2);
}

void nm_win_ts_set_future_timestamp(np_timestamp* ts, uint32_t ms)
{
    nm_win_ts_now(ts);
    *ts = *ts + ms;
}

void nm_win_ts_now(np_timestamp* ts)
{
	SYSTEMTIME st;
	FILETIME ft;
	np_timestamp time;
	GetSystemTime(&st);
	SystemTimeToFileTime(&st, &ft);
	time = ft.dwHighDateTime;
	time << 32;
	time |= ft.dwLowDateTime;

	time /= 10000;
    *ts = time;
}

uint32_t nm_win_ts_difference(np_timestamp* t1, np_timestamp* t2)
{
    if(*t1<*t2) {
        return 0;
    } else {
        return *t1-*t2;
    }
}

uint32_t nm_win_ts_now_ms()
{
    np_timestamp ts;
	nm_win_ts_now(&ts);
    return (uint32_t)ts;
}
