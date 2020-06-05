#ifndef NP_TIMESTAMP_H
#define NP_TIMESTAMP_H

#include <platform/np_types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_timestamp_functions;

struct np_timestamp {
    const struct np_timestamp_functions* vptr;
    // Pointer to data which is implementation specific
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
    uint32_t (*now_ms)(struct np_timestamp* obj);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
