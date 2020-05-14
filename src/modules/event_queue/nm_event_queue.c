#include "nm_event_queue.h"

#include <stdlib.h>


void nm_event_queue_init(struct nm_event_queue* queue)
{
    nn_llist_init(&queue->events);
    nn_llist_init(&queue->timedEvents);

}

void nm_event_queue_deinit(struct nm_event_queue* queue)
{

}

// see np_event_queue for documentation on the following functions.
np_error_code nm_event_queue_create_event(struct np_platform* pl, np_event_callback cb, void* data, struct np_event** event)
{
    struct np_event* ev = calloc(1, sizeof(struct np_event));
    if (ev == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ev->pl = pl;
    ev->cb = cb;
    ev->data = data;

    *event = ev;
    return NABTO_EC_OK;
}

void nm_event_queue_destroy_event(struct np_event* event)
{
    nm_event_queue_cancel_event(event);
    free(event);
}

void nm_event_queue_post_event(struct np_event* event)
{
    // todo check if the event is already in the list and print an error if so
    struct np_platform* pl = event->pl;
    struct nm_event_queue* eq = pl->eqData;
    nn_llist_append(&eq->events, &event->eventsNode, event);
}

void nm_event_queue_post_event_maybe_double(struct np_event* event)
{
    // TODO check if event is already in the list
    struct np_platform* pl = event->pl;
    struct nm_event_queue* eq = pl->eqData;
    nn_llist_append(&eq->events, &event->eventsNode, event);
}

void nm_event_queue_cancel_event(struct np_event* event)
{
    // TODO
}

np_error_code nm_event_queue_create_timed_event(struct np_platform* pl, np_timed_event_callback cb, void* data, struct np_timed_event** event)
{
    struct np_timed_event* ev = calloc(1, sizeof(struct np_timed_event));
    if (ev == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ev->pl = pl;
    ev->cb = cb;
    ev->data = data;

    *event = ev;
    return NABTO_EC_OK;
}

void nm_event_queue_destroy_timed_event(struct np_timed_event* event)
{
    nm_event_queue_cancel_timed_event(event);
    free(event);
}

void nm_event_queue_post_timed_event(struct np_timed_event* event, uint32_t milliseconds)
{
    struct np_platform* pl = event->pl;
    struct nm_event_queue* eq = pl->eqData;

    uint32_t timestamp = np_timestamp_now_ms(pl);
    timestamp += milliseconds;

    struct nn_llist_iterator it = nn_llist_begin(&eq->timedEvents);
    while (!nn_llist_is_end(&it)) {
        struct np_timed_event* timedEvent = nn_llist_get_item(&it);
        if (np_timestamp_less_or_equal(timestamp, timedEvent->expireTimestamp)) {
            nn_llist_insert_before(&it, &event->timedEventsNode, event);
            return;
        }
    }
    // the event is not added to the list simply because it should be at the very end.
    nn_llist_append(&eq->timedEvents, &event->timedEventsNode, event);
}

void nm_event_queue_cancel_timed_event(struct np_timed_event* event)
{
    // TODO
}


/**
 * run a single event on the queue if an event exits.
 *
 * @return true iff an event was executed.
 */
bool nm_event_queue_run_event(struct nm_event_queue* queue)
{
    struct nn_llist_iterator it = nn_llist_begin(&queue->events);
    if (nn_llist_is_end(&it)) {
        return false;
    }

    struct np_event* event = nn_llist_get_item(&it);
    nn_llist_erase(&it);
    event->cb(event->data);
    return true;
}

/**
 * run a single timed event if a timed event exists and ready to be run.
 *
 * @return true iff a timed event was executed
 */
bool nm_event_queue_run_timed_event(struct nm_event_queue* queue, uint32_t now)
{
    struct nn_llist_iterator it = nn_llist_begin(&queue->timedEvents);

    if (nn_llist_is_end(&it)) {
        return false;
    }

    struct np_timed_event* event = nn_llist_get_item(&it);
    if (np_timestamp_less_or_equal(event->expireTimestamp, now)) {
        nn_llist_erase(&it);
        event->cb(NABTO_EC_OK, event->data);
        return true;
    }

    return false;
}

/**
 * Get the timestamp of the next event on the event queue.
 *
 * @return true iff an event exists and its assoicated timestamp is
 * copied to nextEvent
 */
bool nm_event_queue_next_timed_event(struct nm_event_queue* queue, uint32_t* nextTime)
{
    struct nn_llist_iterator it = nn_llist_begin(&queue->timedEvents);

    if (nn_llist_is_end(&it)) {
        return false;
    }

    struct np_timed_event* event = nn_llist_get_item(&it);
    *nextTime = event->expireTimestamp;
    return true;
}
