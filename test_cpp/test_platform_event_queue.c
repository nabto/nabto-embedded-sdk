#include "test_platform_event_queue.h"


#include "test_platform_event_queue.h"

#include <platform/np_logging.h>
#include <platform/np_event_queue.h>
#include <platform/np_platform.h>

#include <stdlib.h>

#include <event2/event.h>

#define LOG NABTO_LOG_MODULE_EVENT_QUEUE

static void init_event(struct np_platform* pl, struct np_event* event, np_event_callback cb, void* data);
static bool post(struct np_event* event);
static void post_maybe_double(struct np_event* event);
static void init_timed_event(struct np_platform* pl, struct np_timed_event* event, np_timed_event_callback cb, void* data);
static void post_timed_event(struct np_timed_event* event, uint32_t milliseconds);
static void cancel(struct np_event* event);
static void cancel_timed_event(struct np_timed_event* timedEvent);

struct test_platform_event_queue {
    struct event_base* eventBase;
};

void test_platform_event_queue_init(struct np_platform* pl, struct event_base* eventBase)
{
    struct test_platform_event_queue* eq = calloc(1, sizeof(struct test_platform_event_queue));

    eq->eventBase = eventBase;
    pl->eqData = eq;

    pl->eq.init_event = &init_event;
    pl->eq.post = &post;
    pl->eq.post_maybe_double = &post_maybe_double;
    pl->eq.init_timed_event = &init_timed_event;
    pl->eq.post_timed_event = &post_timed_event;
    pl->eq.cancel = &cancel;
    pl->eq.cancel_timed_event = &cancel_timed_event;
}

void test_platform_event_queue_deinit(struct np_platform* pl)
{
    struct test_platform_event_queue* eq = pl->eqData;
    event_base_loopbreak(eq->eventBase);
}

void handle_timed_event(evutil_socket_t s, short events, void* data)
{
    NABTO_LOG_TRACE(LOG, "handle timed event");
    struct np_timed_event* timedEvent = data;
//    struct np_platform* pl = timedEvent->pl;
//    struct test_plaform_event_queue* eq = pl->eqData;

//    nabto_device_threads_mutex_lock(eq->mutex);
    timedEvent->cb(NABTO_EC_OK, timedEvent->data);
//    nabto_device_threads_mutex_unlock(eq->mutex);
}

void handle_event(evutil_socket_t s, short events, void* data)
{
    NABTO_LOG_TRACE(LOG, "handle event");
    struct np_event* event = data;
//    struct np_platform* pl = event->pl;
//    struct test_platform_event_queue* eq = pl->eqData;

//    nabto_device_threads_mutex_lock(eq->mutex);
    event->cb(event->data);
//    nabto_device_threads_mutex_unlock(eq->mutex);
}

void init_event(struct np_platform* pl, struct np_event* event, np_event_callback cb, void* data)
{
    event->pl = pl;
    event->cb = cb;
    event->data = data;

    struct test_platform_event_queue* eq = pl->eqData;
    event_assign(&event->event, eq->eventBase, -1, 0, &handle_event, event);
}

bool post(struct np_event* event)
{
    NABTO_LOG_TRACE(LOG, "post event");
    //struct np_platform* pl = event->pl;
    //struct nabto_device_event_queue* eq = pl->eqData;
    event_active(&event->event, 0, 0);
    return true;
}

void post_maybe_double(struct np_event* event)
{
    // TODO
    //struct np_platform* pl = event->pl;
    //struct nabto_device_event_queue* eq = pl->eqData;
    event_active(&event->event, 0, 0);
}

void init_timed_event(struct np_platform* pl, struct np_timed_event* event, np_timed_event_callback cb, void* data)
{
    //struct np_platform* pl = event->pl;
    struct test_platform_event_queue* eq = pl->eqData;
    event->pl = pl;
    event->cb = cb;
    event->data = data;

    event_assign(&event->event, eq->eventBase, -1, 0, &handle_timed_event, event);
}

void post_timed_event(struct np_timed_event* event, uint32_t milliseconds)
{
    //struct np_platform* pl = event->pl;
    //struct nabto_device_event_queue* eq = pl->eqData;
    struct timeval tv;
    tv.tv_sec = (milliseconds / 1000);
    tv.tv_usec = ((milliseconds % 1000) * 1000);
    event_add (&event->event, &tv);
}

void cancel(struct np_event* event)
{
    event_del(&event->event);
}

void cancel_timed_event(struct np_timed_event* timedEvent)
{
    event_del(&timedEvent->event);
}
