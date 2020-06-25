#include "thread_event_queue.h"

#include <modules/event_queue/nm_event_queue.h>

#include <platform/np_timestamp_wrapper.h>

#include <stdlib.h>

struct np_event {
    struct thread_event_queue* queue;
    struct nm_event_queue_event event;
};

static np_error_code create_event(struct np_event_queue* obj, np_event_callback cb, void* cbData, struct np_event** event);
static void destroy_event(struct np_event* event);
static void post_event(struct np_event* event);
static void post_event_maybe_double(struct np_event* event);

static void cancel_event(struct np_event* event);

static void post_timed_event(struct np_event* event, uint32_t milliseconds);

static void* queue_thread(void* data);

static struct np_event_queue_functions module = {
    .create = &create_event,
    .destroy = &destroy_event,
    .post = &post_event,
    .post_maybe_double = &post_event_maybe_double,
    .cancel = &cancel_event,
    .post_timed = &post_timed_event,
};

struct np_event_queue thread_event_queue_get_impl(struct thread_event_queue* queue)
{
    struct np_event_queue eq;
    eq.mptr = &module;
    eq.data = queue;
    return eq;
}

void thread_event_queue_init(struct thread_event_queue* queue, struct nabto_device_mutex* coreMutex, struct np_timestamp* ts)
{
    nm_event_queue_init(&queue->eventQueue);
    queue->stopped = false;
    queue->coreMutex = coreMutex;
    queue->ts = *ts;
    queue->queueThread = NULL;
    queue->queueMutex = nabto_device_threads_create_mutex();
    queue->condition = nabto_device_threads_create_condition();
}

void thread_event_queue_run(struct thread_event_queue* queue)
{
    nabto_device_threads_mutex_lock(queue->queueMutex);
    queue->queueThread = nabto_device_threads_create_thread();
    if (nabto_device_threads_run(queue->queueThread, queue_thread, queue) != 0) {
        // TODO
    }
    nabto_device_threads_mutex_unlock(queue->queueMutex);
}

void thread_event_queue_deinit(struct thread_event_queue* queue)
{
    nabto_device_threads_mutex_lock(queue->queueMutex);
    // stop queue
    if (queue->queueThread != NULL) {
        nabto_device_threads_free_thread(queue->queueThread);
    }
    nabto_device_threads_mutex_unlock(queue->queueMutex);
    nabto_device_threads_free_cond(queue->condition);
    nabto_device_threads_free_mutex(queue->queueMutex);
}



void thread_event_queue_stop_blocking(struct thread_event_queue* queue)
{
    nabto_device_threads_mutex_lock(queue->queueMutex);
    queue->stopped = true;
    nabto_device_threads_mutex_unlock(queue->queueMutex);
    nabto_device_threads_cond_signal(queue->condition);
    if (queue->queueThread != NULL) {
        nabto_device_threads_join(queue->queueThread);
    }
}


np_error_code create_event(struct np_event_queue* obj, np_event_callback cb, void* cbData, struct np_event** event)
{
    struct np_event* ev = calloc(1, sizeof(struct np_event));
    if (ev == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    nm_event_queue_event_init(&ev->event, cb, cbData);
    ev->queue = obj->data;
    *event = ev;
    return NABTO_EC_OK;
}

void destroy_event(struct np_event* event)
{
    struct thread_event_queue* eq = event->queue;
    nabto_device_threads_mutex_lock(eq->queueMutex);
    nm_event_queue_event_deinit(&event->event);
    free(event);
    nabto_device_threads_mutex_unlock(eq->queueMutex);
}

void post_event(struct np_event* event)
{
    struct thread_event_queue* queue = event->queue;
    nabto_device_threads_mutex_lock(queue->queueMutex);
    nm_event_queue_post_event(&queue->eventQueue, &event->event);
    nabto_device_threads_mutex_unlock(queue->queueMutex);
    nabto_device_threads_cond_signal(queue->condition);
}

void post_event_maybe_double(struct np_event* event)
{
    struct thread_event_queue* queue = event->queue;
    nabto_device_threads_mutex_lock(queue->queueMutex);
    nm_event_queue_post_event_maybe_double(&queue->eventQueue, &event->event);
    nabto_device_threads_mutex_unlock(queue->queueMutex);
    nabto_device_threads_cond_signal(queue->condition);
}

void cancel_event(struct np_event* event)
{
    struct thread_event_queue* queue = event->queue;
    nabto_device_threads_mutex_lock(queue->queueMutex);
    nm_event_queue_cancel_event(&event->event);
    nabto_device_threads_mutex_unlock(queue->queueMutex);
}

void post_timed_event(struct np_event* event, uint32_t milliseconds)
{
    struct thread_event_queue* queue = event->queue;

    uint32_t now = np_timestamp_now_ms(&queue->ts);
    uint32_t timestamp = now + milliseconds;
    nabto_device_threads_mutex_lock(queue->queueMutex);
    nm_event_queue_post_timed_event(&queue->eventQueue, &event->event, timestamp);
    nabto_device_threads_mutex_unlock(queue->queueMutex);
    nabto_device_threads_cond_signal(queue->condition);
}

void* queue_thread(void* data)
{
    struct thread_event_queue* queue = data;
    while(true) {
        uint32_t nextEvent;
        uint32_t now = np_timestamp_now_ms(&queue->ts);
        struct nm_event_queue_event* event = NULL;



        nabto_device_threads_mutex_lock(queue->queueMutex);
        if (nm_event_queue_take_event(&queue->eventQueue, &event)) {
            // ok execute the event later.
        } else if (nm_event_queue_take_timed_event(&queue->eventQueue, now, &event)) {
            // ok execute the event later.
        } else if (nm_event_queue_next_timed_event(&queue->eventQueue, &nextEvent)) {
            int32_t diff = np_timestamp_difference(nextEvent, now);
            // ok wait for event to become ready
            nabto_device_threads_cond_timed_wait(queue->condition, queue->queueMutex, diff);
        } else if (queue->stopped) {
            nabto_device_threads_mutex_unlock(queue->queueMutex);
            return NULL;
        } else {
            nabto_device_threads_cond_wait(queue->condition, queue->queueMutex);
        }

        nabto_device_threads_mutex_unlock(queue->queueMutex);


        if (event != NULL) {
            nabto_device_threads_mutex_lock(queue->coreMutex);
            event->cb(event->data);
            nabto_device_threads_mutex_unlock(queue->coreMutex);
        }


    }
    return NULL;
}
