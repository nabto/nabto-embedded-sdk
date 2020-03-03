#ifndef _NP_RANDOM_H_
#define _NP_RANDOM_H_

#ifdef __cplusplus
extern "C" {
#endif

struct np_random_module {
    np_error_code (*random)(struct np_platform* pl, void* buffer, size_t bufferLength);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
