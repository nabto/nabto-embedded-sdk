#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <nabto/nabto_device.h>
#include <nn/log.h>

#ifdef __cplusplus
extern "C" {
#endif

void logging_init(NabtoDevice* device, struct nn_log* logger, const char* logLevel);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
