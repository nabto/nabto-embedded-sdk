#ifndef _NABTO_DEVICE_ERROR_H_
#define _NABTO_DEVICE_ERROR_H_

#include <nabto/nabto_device.h>
#include <platform/np_error_code.h>

NabtoDeviceError nabto_device_error_core_to_api(np_error_code ec);

#endif
