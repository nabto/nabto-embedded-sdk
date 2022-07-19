#ifndef _NABTO_DEVICE_ERROR_H_
#define _NABTO_DEVICE_ERROR_H_

#include <nabto/nabto_device.h>
#include <platform/np_error_code.h>

// List of all the np_error_code.h error codes which is exposed through the nabto_device api.

#define NABTO_DEVICE_ERROR_CODE_MAPPING(XX) \
  XX(OK) \
  XX(UNKNOWN) \
  XX(NOT_IMPLEMENTED) \
  XX(OUT_OF_MEMORY) \
  XX(STRING_TOO_LONG) \
  XX(OPERATION_IN_PROGRESS) \
  XX(FUTURE_NOT_RESOLVED) \
  XX(ABORTED) \
  XX(STOPPED) \
  XX(EOF) \
  XX(INVALID_STATE) \
  XX(INVALID_ARGUMENT) \
  XX(INVALID_CONNECTION) \
  XX(NO_DATA) \
  XX(IN_USE) \
  XX(ADDRESS_IN_USE) \
  XX(NOT_ATTACHED) \
  XX(FAILED) \


NabtoDeviceError nabto_device_error_core_to_api(np_error_code ec);

#endif
