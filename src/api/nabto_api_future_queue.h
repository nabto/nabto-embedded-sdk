#ifndef NABTO_API_FUTURE_QUEUE_H
#define NABTO_API_FUTURE_QUEUE_H

#include <nabto/nabto_device.h>

void nabto_api_future_queue_execute_all(NabtoDeviceFuture* head);

void nabto_api_future_queue_post(NabtoDeviceFuture* head, NabtoDeviceFuture* future);

#endif // NABTO_API_FUTURE_QUEUE_H
