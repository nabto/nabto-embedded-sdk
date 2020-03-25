#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <nabto/nabto_device.h>
#include <nn/log.h>


void device_log(NabtoDeviceLogMessage* msg, void* data);

void log_function(enum nn_log_severity severity, const char* module, const char* file, int line, const char* fmt, va_list args);


#endif
