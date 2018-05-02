#include "event_queue.h"
#include <platform/platform.h>

static void nabto_timed_event_bubble_up();
static void nabto_timed_event_insert(struct nabto_timed_event* prev, struct nabto_timed_event* event);


void nabto_event_queue_post(struct nabto_platform* pl, struct nabto_event* event, nabto_event_callback cb, void* data)
{
    event->next = NULL;
    event->cb = cb;
    event->data = data;

    struct nabto_event_list* ev = &pl->eq.events;
    
    if (ev->head == NULL && ev->tail == NULL) {
        ev->head = event;
        ev->tail = event;
    } else {
        ev->tail->next = event;
        ev->tail = event;
    }
}

void nabto_event_queue_poll_one(struct nabto_platform* pl)
{
    struct nabto_event_list* ev = &pl->eq.events;
    // No events
    if (ev->head == NULL) {
        return;
    }

    // first remove the event from the queue such that a new event can
    // be enqueued in the handling of the event.
    struct nabto_event* event;


    
    if (ev->head == ev->tail) {
        // one event
        event = ev->head;
        ev->head = NULL;
        ev->tail = NULL;
    } else {
        // more than one event
        event = ev->head;
        struct nabto_event* next = ev->head->next;
        ev->head = next;
    }

    event->cb(event->data);
}

void nabto_event_queue_poll_one_timed_event(struct nabto_platform* pl)
{
    struct nabto_timed_event_list* ev = &pl->eq.timedEvents;
    if (ev->head == NULL) {
        return;
    }
    
    struct nabto_timed_event* event = ev->head;
    ev->head = event->next;

    event->cb(NABTO_EC_OK, event->data);
}


bool nabto_event_queue_is_event_queue_empty(struct nabto_platform* pl)
{
    struct nabto_event_list* ev = &pl->eq.events;
    return (ev->head == NULL);
}


void nabto_event_queue_post_timed_event(struct nabto_platform* pl, struct nabto_timed_event* event, uint32_t milliseconds, nabto_timed_event_callback cb, void* data)
{
    struct nabto_timed_event_list* ev = &pl->eq.timedEvents;
    event->next = NULL;
    event->cb = cb;
    event->data = data;
    pl->ts.set_future_timestamp(&event->timestamp, milliseconds);

    if (ev->head == NULL) {
        ev->head = event;
    } else {
        nabto_timed_event_bubble_up(pl, event);
    }
}


/**
 * bubble up a timed event such that it has the right location in the
 * linked list.
 */
void nabto_timed_event_bubble_up(struct nabto_platform* pl, struct nabto_timed_event* event)
{
    struct nabto_timed_event_list* ev = &pl->eq.timedEvents;
    struct nabto_timed_event* next;
    struct nabto_timed_event* current;
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
    nabto_timed_event_insert(current, event);
}

/**
 * Insert a timed event in the queue where place is currently.
 */
void nabto_timed_event_insert(struct nabto_timed_event* prev, struct nabto_timed_event* event)
{
    struct nabto_timed_event* currentNext = prev->next;
    prev->next = event;
    event->next = currentNext;
}

/**
 *
 */
bool nabto_event_queue_has_timed_event(struct nabto_platform* pl)
{
    struct nabto_timed_event_list* ev = &pl->eq.timedEvents;
    return (ev->head != NULL);
}

bool nabto_event_queue_has_ready_timed_event(struct nabto_platform* pl)
{
    struct nabto_timed_event_list* ev = &pl->eq.timedEvents;
    if (ev->head == NULL) {
        return false;
    }

    if (pl->ts.passed_or_now(&ev->head->timestamp)) {
        return true;
    }
    return false;
}

uint32_t nabto_event_queue_next_timed_event_occurance(struct nabto_platform* pl)
{
    nabto_timestamp now;
    struct nabto_timed_event_list* ev = &pl->eq.timedEvents;
    if (ev->head == NULL) {
        return 0;
    }
    pl->ts.now(&now);
    return pl->ts.difference(&ev->head->timestamp, &now);
}
