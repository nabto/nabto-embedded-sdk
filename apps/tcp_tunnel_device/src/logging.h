#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <nabto/nabto_device.h>
#include <nn/log.h>

void init_logging(NabtoDevice* device, struct nn_log* logger, const char* logLevel);

#endif
