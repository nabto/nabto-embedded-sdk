#include "nabto_api_future_queue.h"

#include <api/nabto_device_future.h>

#include <platform/np_logging.h>

bool nabto_api_future_queue_is_empty(struct nabto_device_context* device)
{
    return (device->queueHead == NULL);
}

void nabto_api_future_queue_execute_all(struct nabto_device_context* device)
{
    struct nabto_device_future* elm;
    nabto_device_threads_mutex_lock(device->futureQueueMutex);
    if (device->queueHead == NULL ) {
        nabto_device_threads_mutex_unlock(device->futureQueueMutex);
        return;
    }
    nabto_device_threads_mutex_unlock(device->futureQueueMutex);
    while (device->queueHead != NULL) {
        nabto_device_threads_mutex_lock(device->futureQueueMutex);
        elm = device->queueHead;
        device->queueHead = device->queueHead->next;
        nabto_device_threads_mutex_unlock(device->futureQueueMutex);
        nabto_device_future_popped(elm);
    }

}

void nabto_api_future_queue_post(struct nabto_device_context* device, struct nabto_device_future* fut)
{
    nabto_device_threads_mutex_lock(device->futureQueueMutex);
    fut->next = device->queueHead;
    device->queueHead = fut;
    nabto_device_threads_mutex_unlock(device->futureQueueMutex);
    nabto_device_threads_cond_signal(device->eventCond);
}
