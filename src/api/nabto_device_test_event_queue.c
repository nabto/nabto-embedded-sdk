#include <nabto/nabto_device_test.h>

#include "nabto_device_future.h"
#include "nabto_device_error.h"
#include "nabto_device_defines.h"

#include <platform/np_logging.h>
#include <platform/np_event_queue_wrapper.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_TEST


/**
 * Test events, post and timed events.
 */

struct event_queue_test {
    struct nabto_device_future* fut;
    struct np_event_queue eq;
    struct np_event* event;
    struct np_event* timedEvent;
    int test;
};

static void test_free_and_resolve(struct event_queue_test* t, np_error_code ec)
{
    nabto_device_future_resolve(t->fut, nabto_device_error_core_to_api(ec));
    np_event_queue_destroy_event(&t->eq, t->event);
    np_event_queue_destroy_event(&t->eq, t->timedEvent);
    free(t);
}

// this is called after the second/timed event resolves
static void handle_timed_event_callback(void* data)
{
    NABTO_LOG_TRACE(LOG, "Callback from the timed event");
    struct event_queue_test* t = data;
    test_free_and_resolve(t, NABTO_EC_OK);
}

// This is called after the first event resolves
static void handle_event_callback(void* data)
{
    struct event_queue_test* t = data;

    np_event_queue_post_timed_event(&t->eq, t->timedEvent, 100 /* milliseconds to defer callback with */);
}

void NABTO_DEVICE_API
nabto_device_test_event_queue(NabtoDevice* device, NabtoDeviceFuture* future)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    struct event_queue_test* t = calloc(1, sizeof(struct event_queue_test));
    t->fut = fut;
    struct np_event_queue* eq = &dev->pl.eq;
    t->eq = dev->pl.eq;
    np_error_code ec = np_event_queue_create_event(eq, handle_event_callback, t, &t->event);
    if (ec != NABTO_EC_OK) {
        return test_free_and_resolve(t, ec);
    }
    ec = np_event_queue_create_event(eq, handle_timed_event_callback, t, &t->timedEvent);
    if (ec != NABTO_EC_OK) {
        return test_free_and_resolve(t, ec);
    }

    np_event_queue_post(eq, t->event);
}
