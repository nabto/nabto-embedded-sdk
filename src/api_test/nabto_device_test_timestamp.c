#include <nabto/nabto_device_test.h>

#include <api/nabto_device_future.h>
#include <api/nabto_device_error.h>
#include <api/nabto_device_defines.h>

#include <platform/np_event_queue_wrapper.h>
#include <platform/np_timestamp_wrapper.h>

#include <stdlib.h>

void NABTO_DEVICE_API nabto_device_test_timestamp(NabtoDevice* device, uint32_t* timestamp)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    *timestamp = np_timestamp_now_ms(&dev->pl.timestamp);
}
