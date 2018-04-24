#include "platform.h"

#include "string.h"

static void nabto_platform_timed_event_bubble_up();
static void nabto_platform_timed_event_insert(struct nabto_platform_timed_event* prev, struct nabto_platform_timed_event* event);

void nabto_platform_init(struct nabto_platform* pl)
{
    memset(pl, 0, sizeof(struct nabto_platform));
}

void nabto_platform_post(struct nabto_platform* pl, struct nabto_platform_event* event, nabto_platform_event_callback cb, void* data)
{
    event->next = NULL;
    event->cb = cb;
    event->data = data;
    
    if (pl->events.head == NULL && pl->events.tail == NULL) {
        pl->events.head = event;
        pl->events.tail = event;
    } else {
        pl->events.tail->next = event;
        pl->events.tail = event;
    }
}

void nabto_platform_poll_one(struct nabto_platform* pl)
{
    // No events
    if (pl->events.head == NULL) {
        return;
    }

    // first remove the event from the queue such that a new event can
    // be enqueued in the handling of the event.
    struct nabto_platform_event* event;

    if (pl->events.head == pl->events.tail) {
        // one event
        event = pl->events.head;
        pl->events.head = NULL;
        pl->events.tail = NULL;
    } else {
        // more than one event
        event = pl->events.head;
        struct nabto_platform_event* next = pl->events.head->next;
        pl->events.head = next;
    }

    event->cb(event->data);
}

void nabto_platform_poll_one_timed_event(struct nabto_platform* pl)
{
    if (pl->timedEvents.head == NULL) {
        return;
    }
    
    struct nabto_platform_timed_event* event = pl->timedEvents.head;
    pl->timedEvents.head = event->next;

    event->cb(NABTO_EC_OK, event->data);
}


bool nabto_platform_is_event_queue_empty(struct nabto_platform* pl)
{
    return (pl->events.head == NULL);
}


void nabto_platform_post_timed_event(struct nabto_platform* pl, struct nabto_platform_timed_event* event, uint32_t milliseconds, nabto_platform_timed_event_callback cb, void* data)
{
    event->next = NULL;
    event->cb = cb;
    event->data = data;
    pl->ts.set_future_timestamp(&event->timestamp, milliseconds);

    if (pl->timedEvents.head == NULL) {
        pl->timedEvents.head = event;
    } else {
        nabto_platform_timed_event_bubble_up(pl, event);
    }
}


/**
 * bubble up a timed event such that it has the right location in the
 * linked list.
 */
void nabto_platform_timed_event_bubble_up(struct nabto_platform* pl, struct nabto_platform_timed_event* event)
{
    struct nabto_platform_timed_event* next;
    struct nabto_platform_timed_event* current;
    current = pl->timedEvents.head;
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
    nabto_platform_timed_event_insert(current, event);
}

/**
 * Insert a timed event in the queue where place is currently.
 */
void nabto_platform_timed_event_insert(struct nabto_platform_timed_event* prev, struct nabto_platform_timed_event* event)
{
    struct nabto_platform_timed_event* currentNext = prev->next;
    prev->next = event;
    event->next = currentNext;
}

/**
 *
 */
bool nabto_platform_has_timed_event(struct nabto_platform* pl)
{
    return (pl->timedEvents.head != NULL);
}

bool nabto_platform_has_ready_timed_event(struct nabto_platform* pl)
{
    if (pl->timedEvents.head == NULL) {
        return false;
    }

    if (pl->ts.passed_or_now(&pl->timedEvents.head->timestamp)) {
        return true;
    }
    return false;
}
