#ifndef NP_TIMESTAMP_H
#define NP_TIMESTAMP_H

#include <platform/np_types.h>

// This module assumes a timestamp type is defined in types.h

// e.g. typedef uint32_t np_timestamp;

struct np_platform;
void np_ts_init(struct np_platform* pl);

struct np_timestamp_module {
    /**
     * return true iff timstamp is passed or equal to now.
     */
    bool (*passed_or_now)(np_timestamp* timestamp);

    /**
     * Is less or equal, return true iff t1 <= t2.
     */
    bool (*less_or_equal)(np_timestamp* t1, np_timestamp* t2);

    /**
     * Set  a timestamp to n milliseconds into the future.
     */
    void (*set_future_timestamp)(np_timestamp* ts, uint32_t milliseconds);
    
    /**
     * Return current timestamp.
     */
    void (*now)(np_timestamp* timestamp);

    /**
     * Return current timestamp as uint32_t 
     */
    uint32_t (*now_ms)(void);
    
    /**
     * Return the difference between timestamps in milliseconds,
     * returns 0 if ts2>ts1
     */
    uint32_t (*difference)(np_timestamp* ts1, np_timestamp* ts2);
};

#endif
