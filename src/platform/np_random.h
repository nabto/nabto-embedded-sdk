#ifndef NP_RANDOM_H_
#define NP_RANDOM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "np_error_code.h"

struct np_random_module {
    /**
     * Generate cryptographic strong random data.
     *
     * @param pl  The platform
     * @param buffer  The buffer to fill with random data
     * @param bufferLength  The length of the buffer
     * @return NABTO_EC_OK  iff the buffer is filled with cryptographic strong random data.
     */
    np_error_code (*random)(struct np_platform* pl, void* buffer, size_t bufferLength);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
