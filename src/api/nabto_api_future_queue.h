#ifndef NABTO_API_FUTURE_QUEUE_H
#define NABTO_API_FUTURE_QUEUE_H

#include <nabto/nabto_device.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nabto_device_future;

void nabto_api_future_queue_execute_all(struct nabto_device_future** queue);

void nabto_api_future_set_error_code(struct nabto_device_future* future, const NabtoDeviceError ec);

void nabto_api_future_queue_post(struct nabto_device_future** head, struct nabto_device_future* future, const NabtoDeviceError ec);

void nabto_api_future_queue_post_ec_set(struct nabto_device_future** head, struct nabto_device_future* future);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NABTO_API_FUTURE_QUEUE_H
