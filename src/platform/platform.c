#include "platform.h"

#include "string.h"

void nabto_platform_init(struct nabto_platform* pl)
{
    memset(pl, 0, sizeof(struct nabto_platform));
}

void nabto_platform_post(struct nabto_platform* pl, struct nabto_platform_event* event, nabto_event_callback cb, void* data)
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

bool nabto_platform_is_event_queue_empty(struct nabto_platform* pl)
{
    return (pl->events.head == NULL);
}
