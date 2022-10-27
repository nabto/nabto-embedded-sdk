#include "interfaces/np_event_queue.h"
#include <platform/np_platform.h>
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_EVENT_QUEUE

np_error_code np_event_queue_create_event(struct np_event_queue* eq, np_event_callback cb, void* data, struct np_event** event)
{
    return eq->mptr->create(eq, cb, data, event);
}

void np_event_queue_destroy_event(struct np_event_queue* eq, struct np_event* event)
{
    if (event == NULL) {
        return;
    }
    eq->mptr->destroy(event);
}

/**
 * Enqueue an event to the event queue.
 */
void np_event_queue_post(struct np_event_queue* eq, struct np_event* event)
{
    eq->mptr->post(event);
}

/**
 * Enqueue an event which maybe already is in the queue. If it is on
 * the queue it is not requeued. These events needs to be initialized with np_event_queue_init_event
 */
bool np_event_queue_post_maybe_double(struct np_event_queue* eq, struct np_event* event)
{
    return eq->mptr->post_maybe_double(event);
}

void np_event_queue_post_timed_event(struct np_event_queue* eq, struct np_event* event, uint32_t milliseconds)
{
    eq->mptr->post_timed(event, milliseconds);
}

void np_event_queue_cancel_event(struct np_event_queue* eq, struct np_event* ev)
{
    eq->mptr->cancel(ev);
}
