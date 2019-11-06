#ifndef NM_API_LOGGING_H_
#define NM_API_LOGGING_H_

#include <stdarg.h>
#include <platform/np_logging.h>
#include <nabto/nabto_device.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nm_api_logging {

};

void nm_api_logging_set_level(uint32_t level);
void nm_api_logging_set_callback(NabtoDeviceLogCallback cb, void* data);
void nm_api_logging_std_out_callback(NabtoDeviceLogMessage* msg, void* data);

#ifdef __cplusplus
} //extern "C"
#endif

#endif  // NM_API_LOGGING_H_
