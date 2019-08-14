#ifndef _NABTO_PLATFORM_H_
#define _NABTO_PLATFORM_H_

#include <platform/np_platform.h>

#include <platform/np_logging.h>

void nabto_device_init_platform(struct np_platform* pl);
void nabto_device_init_platform_modules(struct np_platform* pl);

int nabto_device_platform_inf_wait();
void nabto_device_platform_read(int nfds);

#endif
