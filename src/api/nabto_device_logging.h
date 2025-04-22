#ifndef NABTO_DEVICE_LOGGING_H_
#define NABTO_DEVICE_LOGGING_H_

#include <nabto/nabto_device.h>
#include <platform/np_logging.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

void nabto_device_logging_init();
void nabto_device_logging_set_level(uint32_t level);
void nabto_device_logging_set_callback(NabtoDeviceLogCallback cb, void* data);
void nabto_device_logging_std_out_callback(NabtoDeviceLogMessage* msg, void* data);

#ifdef __cplusplus
} //extern "C"
#endif

#endif  // _NABTO_DEVICE_LOGGING_H_
