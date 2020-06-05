#include "interfaces/np_event_queue.h"
#include <platform/np_platform.h>
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_EVENT_QUEUE

np_error_code np_event_queue_create_event(struct np_platform* pl, np_event_callback cb, void* data, struct np_event** event)
{
    return pl->eq.vptr->create(&pl->eq, cb, data, event);
}

void np_event_queue_destroy_event(struct np_platform* pl, struct np_event* event)
{
    return pl->eq.vptr->destroy(event);
}

/**
 * Enqueue an event to the event queue.
 */
void np_event_queue_post(struct np_platform* pl, struct np_event* event)
{
    pl->eq.vptr->post(event);
}

/**
 * Enqueue an event which maybe already is in the queue. If it is on
 * the queue it is not requeued. These events needs to be initialized with np_event_queue_init_event
 */
void np_event_queue_post_maybe_double(struct np_platform* pl, struct np_event* event)
{
    pl->eq.vptr->post_maybe_double(event);
}

void np_event_queue_post_timed_event(struct np_platform* pl, struct np_event* event, uint32_t milliseconds)
{
    pl->eq.vptr->post_timed(event, milliseconds);
}

void np_event_queue_cancel_event(struct np_platform* pl, struct np_event* ev)
{
    pl->eq.vptr->cancel(ev);
}
