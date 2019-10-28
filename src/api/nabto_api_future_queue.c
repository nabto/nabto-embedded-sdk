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
    if (device->queueHead == NULL ) {
        return;
    }
    while (device->queueHead != NULL) {
        elm = device->queueHead;
        device->queueHead = device->queueHead->next;
        nabto_device_future_popped(elm);
    }

}

void nabto_api_future_queue_post(struct nabto_device_context* device, struct nabto_device_future* fut)
{
    fut->next = device->queueHead;
    device->queueHead = fut;
}
