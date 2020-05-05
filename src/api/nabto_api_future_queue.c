#include "nabto_api_future_queue.h"

#include <api/nabto_device_future.h>
#include "nabto_device_event_queue.h"

#include <platform/np_logging.h>



void nabto_api_future_queue_post(struct nabto_device_context* device, struct nabto_device_future* fut)
{
    nabto_device_event_queue_future_post(&device->pl, fut);
}
