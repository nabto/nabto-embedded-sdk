#include "np_event_queue.h"
#include <platform/np_platform.h>
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_EVENT_QUEUE

np_error_code np_event_queue_create_event(struct np_platform* pl, np_event_callback cb, void* data, struct np_event** event)
{
    return pl->eq.create_event(pl->eqData, cb, data, event);
}

void np_event_queue_destroy_event(struct np_platform* pl, struct np_event* event)
{
    return pl->eq.destroy_event(event);
}

/**
 * Enqueue an event to the event queue.
 */
void np_event_queue_post(struct np_platform* pl, struct np_event* event)
{
    pl->eq.post(event);
}

/**
 * Enqueue an event which maybe already is in the queue. If it is on
 * the queue it is not requeued. These events needs to be initialized with np_event_queue_init_event
 */
void np_event_queue_post_maybe_double(struct np_platform* pl, struct np_event* event)
{
    pl->eq.post_maybe_double(event);
}

np_error_code np_event_queue_create_timed_event(struct np_platform* pl, np_timed_event_callback cb, void* data, struct np_timed_event** event)
{
    return pl->eq.create_timed_event(pl->eqData, cb, data, event);
}

void np_event_queue_destroy_timed_event(struct np_platform* pl, struct np_timed_event* event)
{
    pl->eq.destroy_timed_event(event);
}

void np_event_queue_post_timed_event(struct np_platform* pl, struct np_timed_event* event, uint32_t milliseconds)
{
    pl->eq.post_timed_event(event, milliseconds);
}

void np_event_queue_cancel_timed_event(struct np_platform* pl, struct np_timed_event* ev)
{
    pl->eq.cancel_timed_event(ev);
}

void np_event_queue_cancel_event(struct np_platform* pl, struct np_event* ev)
{
    pl->eq.cancel(ev);
}
