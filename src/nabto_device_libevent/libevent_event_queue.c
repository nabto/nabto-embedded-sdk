#include "libevent_event_queue.h"

#include <api/nabto_device_future.h>
#include <api/nabto_device_threads.h>

#include <platform/np_allocator.h>
#include <platform/np_logging.h>

#include <event.h>
#include <event2/event.h>

#define LOG NABTO_LOG_MODULE_EVENT_QUEUE

static np_error_code create(struct np_event_queue* obj, np_event_callback cb, void* cbData, struct np_event** event);
static void destroy(struct np_event* event);
static void post(struct np_event* event);
static bool post_maybe_double(struct np_event* event);

static void post_timed(struct np_event* event, uint32_t milliseconds);
static void cancel(struct np_event* event);

static void handle_event(evutil_socket_t s, short events, void* data);

struct libevent_event_queue {
    struct nabto_device_mutex* mutex;
    struct nabto_device_thread* coreThread;
    struct event_base* eventBase;
};

struct np_event {
    struct libevent_event_queue* eq;
    np_event_callback cb;
    void* data;
    struct event event;
    bool posted;
};

static struct np_event_queue_functions module = {
    .create = &create,
    .destroy = &destroy,
    .post = &post,
    .post_maybe_double = &post_maybe_double,
    .cancel = &cancel,
    .post_timed = &post_timed
};

struct np_event_queue libevent_event_queue_create(struct event_base* eventBase, struct nabto_device_mutex* mutex)
{
    struct np_event_queue obj = {
        .mptr = NULL,
        .data = NULL
    };

    struct libevent_event_queue* eq = np_calloc(1, sizeof(struct libevent_event_queue));
    if (eq == NULL) {
        return obj;
    }
    eq->eventBase = eventBase;
    eq->mutex = mutex;

    obj.mptr = &module;
    obj.data = eq;
    return obj;
}

void libevent_event_queue_destroy(struct np_event_queue* obj)
{
    np_free(obj->data);
}

void handle_event(evutil_socket_t s, short events, void* data)
{
    (void)s; (void)events;
//    NABTO_LOG_TRACE(LOG, "handle event");
    struct np_event* event = data;
    struct libevent_event_queue* eq = event->eq;

    nabto_device_threads_mutex_lock(eq->mutex);
    event->posted = false;
    event->cb(event->data);
    nabto_device_threads_mutex_unlock(eq->mutex);
}

np_error_code create(struct np_event_queue* obj, np_event_callback cb, void* cbData, struct np_event** event)
{
    struct np_event* ev = np_calloc(1, sizeof(struct np_event));
    if (ev == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    struct libevent_event_queue* eq = obj->data;
    ev->eq = eq;
    ev->cb = cb;
    ev->data = cbData;
    ev->posted = false;

    int ec = event_assign(&ev->event, eq->eventBase, -1, 0, &handle_event, ev);
    if (ec != 0) {
        NABTO_LOG_ERROR(LOG, "cannot assign event %d", ec);
        return NABTO_EC_UNKNOWN;
    }

    *event = ev;
    return NABTO_EC_OK;
}

void destroy(struct np_event* event)
{
    cancel(event);
    np_free(event);
}

void post(struct np_event* event)
{
    //NABTO_LOG_TRACE(LOG, "post event");
    //struct np_platform* pl = event->pl;
    //struct nabto_device_event_queue* eq = pl->eqData;
    event->posted = true;
    event_active(&event->event, 0, 0);
}

bool post_maybe_double(struct np_event* event)
{
    if (event->posted) {
        return false;
    }
    event->posted = true;
    event_active(&event->event, 0, 0);
    return true;
}

void post_timed(struct np_event* event, uint32_t milliseconds)
{
    //struct np_platform* pl = event->pl;
    //struct nabto_device_event_queue* eq = pl->eqData;
    struct timeval tv;
    tv.tv_sec = (milliseconds / 1000);
    // due to %1000 this will always be below 1000000, just cast to long
    tv.tv_usec = (long)((milliseconds % 1000) * 1000);
    int ec = event_add (&event->event, &tv);
    if (ec != 0) {
        NABTO_LOG_ERROR(LOG, "Cannot add event %d", ec);
    }
}

void cancel(struct np_event* event)
{
    event_del(&event->event);
}
