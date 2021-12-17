#include "nm_event_queue.h"

#include <platform/np_logging.h>
#include <platform/np_timestamp_wrapper.h>



#define LOG NABTO_LOG_MODULE_EVENT_QUEUE

void nm_event_queue_init(struct nm_event_queue* queue)
{
    nn_llist_init(&queue->events);
    nn_llist_init(&queue->timedEvents);

}

void nm_event_queue_deinit(struct nm_event_queue* queue)
{
    (void)queue;

}

// see np_event_queue for documentation on the following functions.
void nm_event_queue_event_init(struct nm_event_queue_event* event, np_event_callback cb, void* data)
{
    event->cb = cb;
    event->data = data;
    nn_llist_node_init(&event->eventsNode);
}

void nm_event_queue_event_deinit(struct nm_event_queue_event* event)
{
    nm_event_queue_cancel_event(event);
}

void nm_event_queue_post_event(struct nm_event_queue* queue, struct nm_event_queue_event* event)
{
    if (nn_llist_node_in_list(&event->eventsNode)) {
        NABTO_LOG_ERROR(LOG, "Double posted event, use the post_maybe_double if this bahavior is intended");
        return;
    }
    nn_llist_append(&queue->events, &event->eventsNode, event);
}

bool nm_event_queue_post_event_maybe_double(struct nm_event_queue* queue, struct nm_event_queue_event* event)
{
    if (nn_llist_node_in_list(&event->eventsNode)) {
        return false;
    }
    nn_llist_append(&queue->events, &event->eventsNode, event);
    return true;
}

void nm_event_queue_cancel_event(struct nm_event_queue_event* event)
{
    if (nn_llist_node_in_list(&event->eventsNode)) {
        nn_llist_erase_node(&event->eventsNode);
    }
}

void nm_event_queue_post_timed_event(struct nm_event_queue* queue, struct nm_event_queue_event* event, uint32_t timestamp)
{
    event->expireTimestamp = timestamp;
    if (nn_llist_node_in_list(&event->eventsNode)) {
        nn_llist_erase_node(&event->eventsNode);
    }

    struct nn_llist_iterator it = nn_llist_begin(&queue->timedEvents);
    while (!nn_llist_is_end(&it)) {
        struct nm_event_queue_event* timedEvent = nn_llist_get_item(&it);
        if (np_timestamp_less_or_equal(timestamp, timedEvent->expireTimestamp)) {
            nn_llist_insert_before(&it, &event->eventsNode, event);
            return;
        }
        nn_llist_next(&it);
    }
    // the event is not added to the list simply because it should be at the very end.
    nn_llist_append(&queue->timedEvents, &event->eventsNode, event);
}

/**
 * take a single event off the queue if an event exits.
 *
 * @return true iff an event is taken off the event queue.
 */
bool nm_event_queue_take_event(struct nm_event_queue* queue, struct nm_event_queue_event** event)
{
    struct nn_llist_iterator it = nn_llist_begin(&queue->events);
    if (nn_llist_is_end(&it)) {
        return false;
    }

    *event = nn_llist_get_item(&it);
    nn_llist_erase(&it);
    return true;
}

/**
 * run a single timed event if a timed event exists and ready to be run.
 *
 * @return true iff a timed event was executed
 */
bool nm_event_queue_take_timed_event(struct nm_event_queue* queue, uint32_t now, struct nm_event_queue_event** event)
{
    struct nn_llist_iterator it = nn_llist_begin(&queue->timedEvents);

    if (nn_llist_is_end(&it)) {
        return false;
    }

    struct nm_event_queue_event* ev = nn_llist_get_item(&it);
    if (np_timestamp_less_or_equal(ev->expireTimestamp, now)) {
        nn_llist_erase(&it);
        *event = ev;
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

    struct nm_event_queue_event* event = nn_llist_get_item(&it);
    *nextTime = event->expireTimestamp;
    return true;
}
