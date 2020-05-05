#ifndef _NP_UNIX_TIMESTAMP_H_
#define _NP_UNIX_TIMESTAMP_H_

#include <platform/np_platform.h>
#include <nabto_types.h>

#ifdef __cplusplus
extern "C" {
#endif

void nm_unix_ts_init(struct np_platform* pl);

bool nm_unix_ts_passed_or_now(np_timestamp* ts);

bool nm_unix_ts_less_or_equal(np_timestamp* t1, np_timestamp* t2);

void nm_unix_ts_set_future_timestamp(np_timestamp* ts, uint32_t ms);

void nm_unix_ts_now(np_timestamp* ts);

uint32_t nm_unix_ts_now_ms(void);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // _NP_UNIX_TIMESTAMP_H_
