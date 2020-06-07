#include <nabto/nabto_device_test.h>

#include "nabto_device_future.h"
#include "nabto_device_error.h"
#include "nabto_device_defines.h"

#include <platform/np_event_queue_wrapper.h>
#include <platform/np_timestamp_wrapper.h>

#include <stdlib.h>

struct timestamp_test {
    struct nabto_device_future* fut;
    uint32_t startTimestamp;
    struct np_event* timedEvent;
    struct np_event_queue eq;
    struct np_timestamp timestamp;
};

static void resolve_and_free_test(struct timestamp_test* t, np_error_code ec)
{
    nabto_device_future_resolve(t->fut, nabto_device_error_core_to_api(ec));
    np_event_queue_destroy_event(&t->eq, t->timedEvent);
    free(t);
}

static void timed_event_callback(void* data)
{
    struct timestamp_test* t = data;
    // check that the timestamp now is more than 50 ms and less than 1
    // seconds into the future, to give it some fail margin.
    uint32_t now = np_timestamp_now_ms(&t->timestamp);

    // now is logically greater than start so the difference should be positive.
    int32_t timePassed = np_timestamp_difference(now, t->startTimestamp);

    if (timePassed > 50 && timePassed < 1000) {
        resolve_and_free_test(t, NABTO_EC_OK);
    } else {
        resolve_and_free_test(t, NABTO_EC_INVALID_STATE);
    }
}

void NABTO_DEVICE_API nabto_device_test_timestamp(NabtoDevice* device, NabtoDeviceFuture* future)
{
    struct timestamp_test* t = calloc(1, sizeof(struct timestamp_test));
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    t->fut = fut;
    t->eq = dev->pl.eq;
    t->timestamp = dev->pl.timestamp;

    t->startTimestamp = np_timestamp_now_ms(&t->timestamp);

    np_error_code ec = np_event_queue_create_event(&t->eq, timed_event_callback, t, &t->timedEvent);
    if(ec != NABTO_EC_OK) {
        return resolve_and_free_test(t, ec);
    }
    np_event_queue_post_timed_event(&t->eq, t->timedEvent, 100);
}
