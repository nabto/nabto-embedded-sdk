#include "nm_epoll.h"

#include <modules/event_queue/nm_event_queue.h>

#include <platform/np_timestamp_wrapper.h>
#include <platform/np_allocator.h>

#include <api/nabto_device_threads.h>


struct np_event {
    struct nm_epoll* epoll;
    struct nm_event_queue_event event;
};

static np_error_code create_event(struct np_event_queue* obj, np_event_callback cb, void* cbData, struct np_event** event);
static void destroy_event(struct np_event* event);
static void post_event(struct np_event* event);
static bool post_event_maybe_double(struct np_event* event);

static void cancel_event(struct np_event* event);

static void post_timed_event(struct np_event* event, uint32_t milliseconds);


static struct np_event_queue_functions module = {
    .create = &create_event,
    .destroy = &destroy_event,
    .post = &post_event,
    .post_maybe_double = &post_event_maybe_double,
    .cancel = &cancel_event,
    .post_timed = &post_timed_event,
};

struct np_event_queue nm_epoll_event_queue_get_impl(struct nm_epoll* epoll)
{
    struct np_event_queue eq;
    eq.mptr = &module;
    eq.data = epoll;
    return eq;
}

np_error_code create_event(struct np_event_queue* obj, np_event_callback cb, void* cbData, struct np_event** event)
{
    struct np_event* ev = np_calloc(1, sizeof(struct np_event));
    if (ev == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    nm_event_queue_event_init(&ev->event, cb, cbData);
    ev->epoll = obj->data;
    *event = ev;
    return NABTO_EC_OK;
}

void destroy_event(struct np_event* event)
{
    struct nabto_device_mutex* mutex = event->epoll->queueMutex;
    nabto_device_threads_mutex_lock(mutex);
    nm_event_queue_event_deinit(&event->event);
    np_free(event);
    nabto_device_threads_mutex_unlock(mutex);
}

void post_event(struct np_event* event)
{
    nabto_device_threads_mutex_lock(event->epoll->queueMutex);
    nm_event_queue_post_event(&event->epoll->eventQueue, &event->event);
    nabto_device_threads_mutex_unlock(event->epoll->queueMutex);
    nm_epoll_notify(event->epoll);

}

bool post_event_maybe_double(struct np_event* event)
{
    bool status;
    nabto_device_threads_mutex_lock(event->epoll->queueMutex);
    status = nm_event_queue_post_event_maybe_double(&event->epoll->eventQueue, &event->event);
    nabto_device_threads_mutex_unlock(event->epoll->queueMutex);
    nm_epoll_notify(event->epoll);
    return status;
}

void cancel_event(struct np_event* event)
{
    nabto_device_threads_mutex_lock(event->epoll->queueMutex);
    nm_event_queue_cancel_event(&event->event);
    nabto_device_threads_mutex_unlock(event->epoll->queueMutex);
}

void post_timed_event(struct np_event* event, uint32_t milliseconds)
{
    uint32_t now = np_timestamp_now_ms(&event->epoll->ts);
    uint32_t timestamp = now + milliseconds;
    nabto_device_threads_mutex_lock(event->epoll->queueMutex);
    nm_event_queue_post_timed_event(&event->epoll->eventQueue, &event->event, timestamp);
    nabto_device_threads_mutex_unlock(event->epoll->queueMutex);

    nm_epoll_notify(event->epoll);

}

bool nm_epoll_event_queue_handle_event(struct nm_epoll* epoll)
{
    uint32_t now = np_timestamp_now_ms(&epoll->ts);
    struct nm_event_queue_event* event = NULL;

    // handle one event or return false if no events exists.
    nabto_device_threads_mutex_lock(epoll->queueMutex);
    if (nm_event_queue_take_event(&epoll->eventQueue, &event)) {
        // ok execute the event later.
    } else if (nm_event_queue_take_timed_event(&epoll->eventQueue, now,
                                               &event)) {
        // ok execute the event later.
    }
    nabto_device_threads_mutex_unlock(epoll->queueMutex);

    if (event != NULL) {
        nabto_device_threads_mutex_lock(epoll->coreMutex);
        event->cb(event->data);
        nabto_device_threads_mutex_unlock(epoll->coreMutex);
        return true;
    }
    return false;
}

bool nm_epoll_event_queue_get_next_timed_event(struct nm_epoll* epoll, int32_t* ms)
{
    uint32_t nextEvent;
    uint32_t now = np_timestamp_now_ms(&epoll->ts);
    bool status = false;
    nabto_device_threads_mutex_lock(epoll->queueMutex);
    if (nm_event_queue_next_timed_event(&epoll->eventQueue, &nextEvent)) {
        *ms = np_timestamp_difference(nextEvent, now);
        status = true;
    }
    nabto_device_threads_mutex_unlock(epoll->queueMutex);

    return status;
}
