#include "np_event_queue.h"
#include <platform/np_platform.h>
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_EVENT_QUEUE

static void np_timed_event_bubble_up(struct np_platform* pl, struct np_timed_event* event);

void np_event_queue_init(struct np_platform* pl, np_event_queue_executor_notify notify, void* notifyData)
{
    struct np_event_queue* eq = &pl->eq;
    eq->notify = notify;
    eq->notifyData = notifyData;

    eq->events.sentinel = &eq->events.sentinelData;
    eq->events.sentinel->next = eq->events.sentinel;
    eq->events.sentinel->prev = eq->events.sentinel;

    eq->timedEvents.sentinel = &eq->timedEvents.sentinelData;
    eq->timedEvents.sentinel->next = eq->timedEvents.sentinel;
    eq->timedEvents.sentinel->prev = eq->timedEvents.sentinel;


}

void np_event_queue_init_event(struct np_event* event)
{
    event->next = event;
    event->prev = event;
}

void np_event_queue_execute_one(struct np_platform* pl)
{
    if(!np_event_queue_is_event_queue_empty(pl)) {
        np_event_queue_poll_one(pl);
    } else if(np_event_queue_has_ready_timed_event(pl)) {
        np_event_queue_poll_one_timed_event(pl);
    }
}

bool np_event_queue_has_ready_event(struct np_platform* pl)
{
    return (!np_event_queue_is_event_queue_empty(pl) || np_event_queue_has_ready_timed_event(pl));
}

void np_event_queue_execute_all(struct np_platform* pl)
{
    while(np_event_queue_has_ready_event(pl)){
        np_event_queue_execute_one(pl);
    }
}

static void insert_event_between_nodes(struct np_event* event, struct np_event* after, struct np_event* before)
{
    after->next = event;
    before->prev = event;
    event->next = before;
    event->prev = after;
}

static void remove_event(struct np_event* event)
{
    struct np_event* before = event->prev;
    struct np_event* after = event->next;
    before->next = after;
    after->prev = before;

    event->next = event;
    event->prev = event;
}

static void remove_timed_event(struct np_timed_event* event)
{
    struct np_timed_event* before = event->prev;
    struct np_timed_event* after = event->next;
    before->next = after;
    after->prev = before;

    event->next = event;
    event->prev = event;
}

bool np_event_queue_post(struct np_platform* pl, struct np_event* event, np_event_callback cb, void* data)
{
    bool canceledEvent = false;
    {
        // remove event if already present in queue TODO this is bad
        // since we are not calling the completion handler exactly
        // once.
        if (np_event_queue_cancel_event(pl, event)) {
            NABTO_LOG_ERROR(LOG, "Double posted event had to be cancelled");
            canceledEvent = true;
        }
    }
    event->cb = cb;
    event->data = data;

    struct np_event* before = pl->eq.events.sentinel->prev;
    struct np_event* after = pl->eq.events.sentinel;

    insert_event_between_nodes(event, before, after);

    if (pl->eq.notify) {
        pl->eq.notify(pl->eq.notifyData);
    }
    return canceledEvent;
}

void np_event_queue_post_maybe_double(struct np_platform* pl, struct np_event* event, np_event_callback cb, void* data)
{
    if (event->next == event && event->prev == event)
    {
        // the event is not posted on the queue.

        event->cb = cb;
        event->data = data;

        struct np_event* before = pl->eq.events.sentinel->prev;
        struct np_event* after = pl->eq.events.sentinel;

        insert_event_between_nodes(event, before, after);

        if (pl->eq.notify) {
            pl->eq.notify(pl->eq.notifyData);
        }
    }
}

void np_event_queue_poll_one(struct np_platform* pl)
{
    struct np_event_list* ev = &pl->eq.events;
    // No events
    if (ev->sentinel->next == ev->sentinel) {
        return;
    }

    // first remove the event from the queue such that a new event can
    // be enqueued in the handling of the event.
    struct np_event* event = ev->sentinel->next;

    remove_event(event);
    event->cb(event->data);
}

void np_event_queue_poll_one_timed_event(struct np_platform* pl)
{
    struct np_timed_event_list* ev = &pl->eq.timedEvents;
    if (ev->sentinel->next == ev->sentinel) {
        return;
    }

    struct np_timed_event* event = ev->sentinel->next;
    struct np_timed_event* after = event->next;

    ev->sentinel->next = after;
    after->prev = ev->sentinel;
    event->cb(NABTO_EC_OK, event->data);
}


bool np_event_queue_is_event_queue_empty(struct np_platform* pl)
{
    struct np_event_list* ev = &pl->eq.events;
    return (ev->sentinel->next == ev->sentinel);
}

static void insert_timed_event_between_nodes(struct np_timed_event* event, struct np_timed_event* after, struct np_timed_event* before)
{
    after->next = event;
    before->prev = event;
    event->next = before;
    event->prev = after;
}

void np_event_queue_post_timed_event(struct np_platform* pl, struct np_timed_event* event, uint32_t milliseconds, np_timed_event_callback cb, void* data)
{
    {
        // if the event is already in the timed queue cancel it first
        // TODO this is not good since we should call the completion
        // handler exactly once.
        if (np_event_queue_cancel_timed_event(pl, event)) {
            NABTO_LOG_ERROR(LOG, "Double posted timed event had to be cancelled");
            //NABTO_LOG_TRACE(LOG, "cancelling queued timed event");
        }
    }
    event->cb = cb;
    event->data = data;
    pl->ts.set_future_timestamp(&event->timestamp, milliseconds);

    struct np_timed_event_list* ev = &pl->eq.timedEvents;

    struct np_timed_event* before = ev->sentinel;
    struct np_timed_event* after = ev->sentinel->next;
    insert_timed_event_between_nodes(event, before, after);

    np_timed_event_bubble_up(pl, event);

    if (ev->sentinel->next == event) {
        // the event has changed the current time for timed events.
        if (pl->eq.notify) {
            pl->eq.notify(pl->eq.notifyData);
        }
    }
}

bool np_event_queue_cancel_timed_event(struct np_platform* pl, struct np_timed_event* event)
{
    struct np_timed_event_list* ev = &pl->eq.timedEvents;

    struct np_timed_event* iterator = ev->sentinel->next;

    while(iterator != ev->sentinel) {
        if (iterator == event) {
            remove_timed_event(iterator);
            return true;
        }
        iterator = iterator->next;
    }
    return false;
}


bool np_event_queue_cancel_event(struct np_platform* pl, struct np_event* event)
{
    struct np_event_list* ev = &pl->eq.events;
    struct np_event* iterator = ev->sentinel->next;
    while(iterator != ev->sentinel) {
        if (iterator == event) {
            remove_event(iterator);
            return true;
        }
        iterator = iterator->next;
    }
    return false;
}


static void swap_timed_events(struct np_timed_event* e1, struct np_timed_event* e2)
{
    struct np_timed_event* before = e1->prev;
    struct np_timed_event* after = e2->next;

    // create forward chain
    before->next = e2;
    e2->next = e1;
    e1->next = after;

    // create backward chain
    after->prev = e1;
    e1->prev = e2;
    e2->prev = before;
}

/**
 * bubble up a timed event such that it has the right location in the
 * linked list.
 */
void np_timed_event_bubble_up(struct np_platform* pl, struct np_timed_event* event)
{
    struct np_timed_event_list* ev = &pl->eq.timedEvents;
    struct np_timed_event* iterator = event;

    while(iterator->next != ev->sentinel && pl->ts.less_or_equal(&iterator->next->timestamp, &iterator->timestamp))
    {
        swap_timed_events(iterator, iterator->next);
    }
}

/**
 *
 */
bool np_event_queue_has_timed_event(struct np_platform* pl)
{
    struct np_timed_event_list* ev = &pl->eq.timedEvents;
    return (ev->sentinel->next != ev->sentinel);
}

bool np_event_queue_has_ready_timed_event(struct np_platform* pl)
{
    struct np_timed_event_list* ev = &pl->eq.timedEvents;
    if (ev->sentinel->next == ev->sentinel) {
        return false;
    }

    if (pl->ts.passed_or_now(&ev->sentinel->next->timestamp)) {
        return true;
    }
    return false;
}

uint32_t np_event_queue_next_timed_event_occurance(struct np_platform* pl)
{
    np_timestamp now;
    struct np_timed_event_list* ev = &pl->eq.timedEvents;
    if (ev->sentinel->next == ev->sentinel) {
        return 0;
    }
    pl->ts.now(&now);
    return pl->ts.difference(&ev->sentinel->next->timestamp, &now);
}

bool np_event_queue_is_event_enqueued(struct np_platform* pl, struct np_event* event)
{
    struct np_event_list* ev = &pl->eq.events;
    struct np_event* iterator = ev->sentinel->next;

    while(iterator != ev->sentinel) {
        if (iterator == event) {
            return true;
        }
        iterator = iterator->next;
    }
    return false;
}
