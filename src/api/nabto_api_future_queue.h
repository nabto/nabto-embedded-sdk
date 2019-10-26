#ifndef NABTO_API_FUTURE_QUEUE_H
#define NABTO_API_FUTURE_QUEUE_H

#include <nabto/nabto_device.h>
#include <api/nabto_device_defines.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nabto_device_future;

void nabto_api_future_queue_execute_all(struct nabto_device_context* device);

void nabto_api_future_queue_post(struct nabto_device_context* device, struct nabto_device_future* future);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NABTO_API_FUTURE_QUEUE_H
