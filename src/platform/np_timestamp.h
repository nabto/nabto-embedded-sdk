#ifndef NP_TIMESTAMP_H
#define NP_TIMESTAMP_H

#include <platform/np_types.h>

#ifdef __cplusplus
extern "C" {
#endif

// This module assumes a timestamp type is defined in types.h

// e.g. typedef uint32_t np_timestamp;

struct np_platform;

struct np_timestamp_module {
    /**
     * Test if a timestamp is from the past or the current now.
     *
     * @param timestamp  The timestamp to compare to now.
     * @return true iff timstamp is passed or equal to now.
     */
    bool (*passed_or_now)(np_timestamp* timestamp);

    /**
     * Test if t1 is less than equal to t2.
     *
     * @param t1  Timestamp 1.
     * @param t2  Timestamp 2.
     * @return True iff t1 <= t2.
     */
    bool (*less_or_equal)(np_timestamp* t1, np_timestamp* t2);

    /**
     * Set a timestamp to n milliseconds into the future.
     *
     * @param ts  The timestamp to set.
     * @param milliseconds  The amount of milliseconds to set the timestamp into the future from now.
     */
    void (*set_future_timestamp)(np_timestamp* ts, uint32_t milliseconds);

    /**
     * Return current timestamp.
     *
     * @param timestamp  The timestamp to write now to.
     */
    void (*now)(np_timestamp* timestamp);

    /**
     * Return current timestamp as uint32_t the result will be
     * truncated and wrapping around.
     *
     * @return  The current timestamp as a truncated uint32_t.
     */
    uint32_t (*now_ms)(void);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
