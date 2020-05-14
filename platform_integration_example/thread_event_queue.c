#include "thread_event_queue.h"

struct thread_event_queue
{
    struct nn_llist eventList;
    struct nn_llist timedEventList;
    struct nabto_device_mutex* mutex;
    struct nabto_device_condition* condition;
    struct nabto_device_thread* thread;
};

struct np_event {
    struct np_platform* pl;
    np_event_callback cb;
    void* data;
    struct nn_llist_node eventListNode;
};

struct np_timed_event {
    struct np_platform* pl;
    np_timed_event_callback cb;
    void* data;
    struct nn_llist_node timedEventListNode;
    uint32_t expireTimestamp;
};

np_event_queue thread_event_queue_init(struct np_platform* pl, struct nabto_device_mutex* mutex)
{
    struct thread_event_queue* eventQueue = calloc(1, sizeof(struct thread_event_queue));
}

void thread_event_queue_deinit(struct np_platform* pl);

np_error_code create_event(struct np_platform* pl, np_event_callback cb, void* data, struct np_event** event)
{
    struct np_event* ev = calloc(1, sizeof(struct np_event));
    if (ev == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ev->pl = pl;
    ev->cb = cb;
    ev->data = data;

    struct thread_event_queue* eq = pl->eqData;

    *event = ev;
    return NABTO_EC_OK;
}

np_error_code create_timed_event(struct np_platform* pl, np_timed_event_callback cb, void* data, struct np_timed_event** event)
{
    struct np_timed_event* ev = calloc(1, sizeof(struct np_timed_event));
    if (ev == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    struct libevent_event_queue* eq = pl->eqData;
    ev->pl = pl;
    ev->cb = cb;
    ev->data = data;

    *event = ev;
    return NABTO_EC_OK;
}

void notify_event_queue(struct thread_event_queue* eq)
{
    nabto_device_threads_cond_notify(eq->condition);
}

bool post(struct np_event* event)
{
    struct np_platform* pl = event->pl;
    struct thread_event_queue* eq = pl->eqData;
    nn_llist_append(&eq->eventList, event);
    notify_event_queue(eq);
    return true;
}

void post_timed_event(struct np_timed_event* event, uint32_t milliseconds)
{
    struct np_platform* pl = event->pl;
    struct thread_event_queue* eq = pl->eqData;

    uint32_t timestamp = np_timestamp_now_ms(pl);
    timestamp += milliseconds;

    struct nn_llist_iterator it = nn_llist_begin(&eq->timedEventList);
    while (!nn_llist_is_end(&it)) {
        struct np_timed_event* timedEvent = nn_llist_item(&it);
        if (np_timestamp_less_or_equal(timestamp, timedEvent->expireTimestamp)) {
            nn_llist_insert_before()
        }

    }

    nn_llist_append(&eq->timedEventList, event);
    notify_event_queue(eq);

    struct timeval tv;
    tv.tv_sec = (milliseconds / 1000);
    tv.tv_usec = ((milliseconds % 1000) * 1000);

    event_add (&event->event, &tv);
}

bool run_timed_event(struct thread_event_queue* eq, uint32_t now)
{
    // precondition we have mutex for the system.
    if (nn_llist_empty(&eq->timedEventList)) {
        return false;
    }
    struct nn_llist_iterator it = nn_llist_begin(&eq->timedEventList);
    struct np_timed_event* event = nn_llist_item(&it);
    if (np_timestamp_less_or_equal(event->expireTimestamp, now)) {
        nn_llist_erase(&it);
        event->cb(event->data);
        return true;
    }

    return false;
}

bool next_timed_event(uint32_t* nextTime)
{
    if (nn_llist_empty(&eq->timedEventList)) {
        return false;
    }
    struct nn_llist_iterator it = nn_llist_begin(&eq->timedEventList);
    struct np_timed_event* event = nn_llist_item(&it);
    *nextTime = event->expireTimestamp;
    return true;
}

bool run_event(struct thread_event_queue* eq)
{
    // precondition we have mutex for the system.
    if (nn_llist_empty(&eq->eventList)) {
        return false;
    }
    struct nn_llist_iterator it = nn_llist_begin(&eq->eventQueue);
    struct np_event* event = nn_llist_item(&it);
    nn_llist_erase(&it);
    event->cb(event->data);
    return true;
}

bool is_stopped(struct thread_event_queue* eq)
{
    return eq->stopped;
}

void* execution_thread(void* data)
{
    struct thread_event_queue* eq = data;
    uint32_t nextTimedEvent;
    while(true) {
        nabto_device_threads_mutex_lock(eq->mutex);
        uint32_t now = np_timestamp_now_ms(eq->pl);
        if (run_event(eq)) {

        } else if (run_timed_event(eq, now)) {

        } else if (is_stopped(eq)) {
            nabto_device_threads_mutex_unlock(eq->mutex);
            return;
        } else {
            if (next_timed_event(eq, &nextTimedEvent)) {
                // all timed events from the past is executed, find the next minimum timestamp
                // so we can substract next from now and get a positive
            } else {
                // no timed events just wait.
                nabto_device_threads_cond_wait(eq->condition, eq->mutex);
            }

        }
        nabto_device_threads_mutex_unlock(eq->mutex);
    }
}
