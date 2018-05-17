#include "np_event_queue.h"
#include <platform/np_platform.h>
#include <platform/np_logging.h>

static void np_timed_event_bubble_up();
static void np_timed_event_insert(struct np_timed_event* prev, struct np_timed_event* event);


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

void np_event_queue_post(struct np_platform* pl, struct np_event* event, np_event_callback cb, void* data)
{
    event->next = NULL;
    event->cb = cb;
    event->data = data;

    struct np_event_list* ev = &pl->eq.events;
    
    if (ev->head == NULL && ev->tail == NULL) {
        ev->head = event;
        ev->tail = event;
    } else {
        ev->tail->next = event;
        ev->tail = event;
    }
}

void np_event_queue_poll_one(struct np_platform* pl)
{
    struct np_event_list* ev = &pl->eq.events;
    // No events
    if (ev->head == NULL) {
        return;
    }

    // first remove the event from the queue such that a new event can
    // be enqueued in the handling of the event.
    struct np_event* event;


    
    if (ev->head == ev->tail) {
        // one event
        event = ev->head;
        ev->head = NULL;
        ev->tail = NULL;
    } else {
        // more than one event
        event = ev->head;
        struct np_event* next = ev->head->next;
        ev->head = next;
    }

    event->cb(event->data);
}

void np_event_queue_poll_one_timed_event(struct np_platform* pl)
{
    struct np_timed_event_list* ev = &pl->eq.timedEvents;
    if (ev->head == NULL) {
        return;
    }
    
    struct np_timed_event* event = ev->head;
    ev->head = event->next;

    event->cb(NABTO_EC_OK, event->data);
}


bool np_event_queue_is_event_queue_empty(struct np_platform* pl)
{
    struct np_event_list* ev = &pl->eq.events;
    return (ev->head == NULL);
}


void np_event_queue_post_timed_event(struct np_platform* pl, struct np_timed_event* event, uint32_t milliseconds, np_timed_event_callback cb, void* data)
{
    struct np_timed_event_list* ev = &pl->eq.timedEvents;
    event->next = NULL;
    event->cb = cb;
    event->data = data;
    pl->ts.set_future_timestamp(&event->timestamp, milliseconds);

    if (ev->head == NULL) {
        ev->head = event;
    } else {
        np_timed_event_bubble_up(pl, event);
    }
}

void np_event_queue_cancel_timed_event(struct np_platform* pl, struct np_timed_event* event)
{
    struct np_timed_event_list* ev = &pl->eq.timedEvents;
    if (ev->head == NULL) {
        return;
    }
    if (ev->head == event) {
        ev->head = ev->head->next;
        return;
    }
    struct np_timed_event* current = ev->head;
    struct np_timed_event* next = current->next;
    NABTO_LOG_TRACE(NABTO_LOG_MODULE_EVENT_QUEUE, "Trying to cancel timed event");
    while(next != NULL) {
        if (next == event) {
            NABTO_LOG_TRACE(NABTO_LOG_MODULE_EVENT_QUEUE, "Found and canceled timed event");
            current->next = next->next;
            return;
        }
        current = current->next;
        next = current->next;
    }
}


/**
 * bubble up a timed event such that it has the right location in the
 * linked list.
 */
void np_timed_event_bubble_up(struct np_platform* pl, struct np_timed_event* event)
{
    struct np_timed_event_list* ev = &pl->eq.timedEvents;
    struct np_timed_event* next;
    struct np_timed_event* current;
    current = ev->head;
    next = current->next;

    while(next != NULL) {
        if (pl->ts.less_or_equal(&next->timestamp, &event->timestamp)) {
            current = current->next;
            next = current->next;
        } else {
            break;
        }
    }

    // next points to where we want to insert the element.

    // if we end here, insert the event as the last event
    // insert the event after the event current points to.
    np_timed_event_insert(current, event);
}

/**
 * Insert a timed event in the queue where place is currently.
 */
void np_timed_event_insert(struct np_timed_event* prev, struct np_timed_event* event)
{
    struct np_timed_event* currentNext = prev->next;
    prev->next = event;
    event->next = currentNext;
}

/**
 *
 */
bool np_event_queue_has_timed_event(struct np_platform* pl)
{
    struct np_timed_event_list* ev = &pl->eq.timedEvents;
    return (ev->head != NULL);
}

bool np_event_queue_has_ready_timed_event(struct np_platform* pl)
{
    struct np_timed_event_list* ev = &pl->eq.timedEvents;
    if (ev->head == NULL) {
        return false;
    }

    if (pl->ts.passed_or_now(&ev->head->timestamp)) {
        return true;
    }
    return false;
}

uint32_t np_event_queue_next_timed_event_occurance(struct np_platform* pl)
{
    np_timestamp now;
    struct np_timed_event_list* ev = &pl->eq.timedEvents;
    if (ev->head == NULL) {
        return 0;
    }
    pl->ts.now(&now);
    return pl->ts.difference(&ev->head->timestamp, &now);
}
