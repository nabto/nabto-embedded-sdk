#ifndef NP_TIMESTAMP_H
#define NP_TIMESTAMP_H

#include <platform/np_types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_platform;
struct np_timestamp_impl;

struct np_timestamp_functions;

struct np_timestamp {
    const struct np_timestamp_functions* vptr;
    void* data;
};

struct np_timestamp_functions {
    /**
     * Return current timestamp as milliseconds the timestamp should
     * be a monotonic value which wraps around whenever the value
     * reaches 2^32. The precision is not critical.
     *
     * @param  data  The timestamp object data.
     * @return  The current timestamp in milliseconds.
     */
    uint32_t (*now_ms)(void* data);
};

/**
 * get current timestamp in milliseconds
 *
 * @return timestamp in milliseconds
 */
uint32_t np_timestamp_now_ms(struct np_platform* pl);

/**
 * @param pl  The platform.
 * @param stamp  The timestamp.
 * @return True iff the timestamp is in the past.
 */
bool np_timestamp_passed_or_now(struct np_platform* pl, uint32_t stamp);

/**
 * @param t1 Timestamp 1
 * @param t2 Timestamp 2
 * @return t1 <= t2 the function implements timestamp wraparound handling.
 */
bool np_timestamp_less_or_equal(uint32_t t1, uint32_t t2);

/**
 * Get a stamp which is n milliseconds into the future.
 *
 * @param pl  The platform
 * @param ms  Amount of milliseconds to set the timestamp into the future.
 * @return the resulting timestamp.
 */
uint32_t np_timestamp_future(struct np_platform* pl, uint32_t ms);

/**
 * Return the difference between timestamps.
 *
 * @param t1  Timestamp t1.
 * @param t2  Timestamp t2.
 * @return t1 - t2
 */
int32_t np_timestamp_difference(uint32_t t1, uint32_t t2);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
