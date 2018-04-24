#ifndef NABTO_TIMESTAMP_H
#define NABTO_TIMESTAMP_H

#include <platform/types.h>

// This module assumes a timestamp type is defined in types.h

// e.g. typedef uint32_t nabto_timestamp;

struct nabto_timestamp_module {
    /**
     * return true iff timstamp is passed or equal to now.
     */
    bool (*passed_or_now)(nabto_timestamp* timestamp);

    /**
     * Is less or equal, return true iff t1 <= t2.
     */
    bool (*less_or_equal)(nabto_timestamp* t1, nabto_timestamp* t2);

    /**
     * Set  a timestamp to n milliseconds into the future.
     */
    void (*set_future_timestamp)(nabto_timestamp* ts, uint32_t milliseconds);
    
    /**
     * Return current timestamp.
     */
    void (*now)(nabto_timestamp* timestamp);
};

#endif
