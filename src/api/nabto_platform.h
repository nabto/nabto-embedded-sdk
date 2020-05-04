#ifndef _NABTO_PLATFORM_H_
#define _NABTO_PLATFORM_H_

#include <platform/np_platform.h>

#include <platform/np_logging.h>

void nabto_device_init_platform(struct np_platform* pl);
void nabto_device_deinit_platform(struct np_platform* pl);
np_error_code nabto_device_init_platform_modules(struct np_platform* pl);
void nabto_device_deinit_platform_modules(struct np_platform* pl);

void nabto_device_platform_stop_blocking(struct np_platform* pl);

#endif
