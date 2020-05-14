#include "select_unix_event_queue.h"
#include "select_unix_notify.h"

#include <modules/event_queue/nm_event_queue.h>

static void post_event(struct np_event* event);
static void post_event_maybe_double(struct np_event* event);
static void post_timed_event(struct np_timed_event* event, uint32_t milliseconds);
static void notify_platform(struct np_platform* pl);

void select_unix_event_queue_init(struct nm_event_queue* eventQueue, struct np_platform* pl)
{
    pl->eqData = eventQueue;
    nm_event_queue_init(eventQueue);
    pl->eq.create_event = &nm_event_queue_create_event;
    pl->eq.destroy_event = &nm_event_queue_destroy_event;
    pl->eq.post = &post_event;
    pl->eq.post_maybe_double = &post_event_maybe_double;
    pl->eq.cancel = &nm_event_queue_cancel_event;
    pl->eq.create_timed_event = &nm_event_queue_create_timed_event;
    pl->eq.destroy_timed_event = &nm_event_queue_destroy_timed_event;
    pl->eq.post_timed_event = &post_timed_event;
    pl->eq.cancel_timed_event = &nm_event_queue_cancel_timed_event;
}

void post_event(struct np_event* event)
{
    nm_event_queue_post_event(event);
    notify_platform(event->pl);
}

void post_event_maybe_double(struct np_event* event)
{
    nm_event_queue_post_event_maybe_double(event);
    notify_platform(event->pl);
}

void post_timed_event(struct np_timed_event* event, uint32_t milliseconds)
{
    nm_event_queue_post_timed_event(event, milliseconds);
    notify_platform(event->pl);
}

void notify_platform(struct np_platform* pl)
{
    select_unix_notify_platform(pl->platformData);
}
