#include <nabto/nabto_device_test.h>

#include <api/nabto_device_future.h>
#include <api/nabto_device_error.h>
#include <api/nabto_device_defines.h>

#include <platform/np_logging.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_timestamp_wrapper.h>
#include <platform/np_heap.h>

#define LOG NABTO_LOG_MODULE_TEST


/**
 * Test events, post and timed events.
 */

struct event_queue_test {
    struct nabto_device_future* fut;
    struct np_event_queue eq;
    struct np_timestamp timestamp;
    struct np_event* event;
    struct np_event* timedEvent;
    uint32_t startTimestamp;
    int test;
};

static void resolve_and_free_test(struct event_queue_test* t, np_error_code ec)
{
    nabto_device_future_resolve(t->fut, nabto_device_error_core_to_api(ec));
    np_event_queue_destroy_event(&t->eq, t->event);
    np_event_queue_destroy_event(&t->eq, t->timedEvent);
    np_free(t);
}

// this is called after the second/timed event resolves
static void handle_timed_event_callback(void* data)
{
    NABTO_LOG_TRACE(LOG, "Callback from the timed event");
    struct event_queue_test* t = data;

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

// This is called after the first event resolves
static void handle_event_callback(void* data)
{
    struct event_queue_test* t = data;

    t->startTimestamp = np_timestamp_now_ms(&t->timestamp);

    np_event_queue_post_timed_event(&t->eq, t->timedEvent, 100 /* milliseconds to defer callback with */);
}

void NABTO_DEVICE_API
nabto_device_test_event_queue(NabtoDevice* device, NabtoDeviceFuture* future)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    struct event_queue_test* t = np_calloc(1, sizeof(struct event_queue_test));
    t->fut = fut;
    struct np_event_queue* eq = &dev->pl.eq;
    t->eq = dev->pl.eq;
    t->timestamp = dev->pl.timestamp;
    np_error_code ec = np_event_queue_create_event(eq, handle_event_callback, t, &t->event);
    if (ec != NABTO_EC_OK) {
        resolve_and_free_test(t, ec);
        return;
    }
    ec = np_event_queue_create_event(eq, handle_timed_event_callback, t, &t->timedEvent);
    if (ec != NABTO_EC_OK) {
        resolve_and_free_test(t, ec);
        return;
    }

    np_event_queue_post(eq, t->event);
}
