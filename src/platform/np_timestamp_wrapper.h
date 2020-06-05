#ifndef _NP_TIMESTAMP_WRAPPER_H_
#define _NP_TIMESTAMP_WRAPPER_H_

#include "interfaces/np_timestamp.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Wrapper functions for the timestamp interface. See np_timestamp.h
 * for help.
 */
uint32_t np_timestamp_now_ms(struct np_timestamp* obj);


/**
 * Timestamp helper functions
 */

/**
 * @param obj  The timestamp object.
 * @param stamp  The timestamp.
 * @return True iff the timestamp is in the past.
 */
bool np_timestamp_passed_or_now(struct np_timestamp* obj, uint32_t stamp);

/**
 * @param t1 Timestamp 1
 * @param t2 Timestamp 2
 * @return t1 <= t2 the function implements timestamp wraparound handling.
 */
bool np_timestamp_less_or_equal(uint32_t t1, uint32_t t2);

/**
 * Get a stamp which is n milliseconds into the future.
 *
 * @param obj  The timestamp object
 * @param ms  Amount of milliseconds to set the timestamp into the future.
 * @return the resulting timestamp.
 */
uint32_t np_timestamp_future(struct np_timestamp* obj, uint32_t ms);

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
