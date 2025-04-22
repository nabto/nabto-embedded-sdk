#ifndef NP_UNIX_TIMESTAMP_H_
#define NP_UNIX_TIMESTAMP_H_

#include <platform/np_platform.h>
#include <platform/np_types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct np_timestamp nm_unix_ts_get_impl(void);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // _NP_UNIX_TIMESTAMP_H_
