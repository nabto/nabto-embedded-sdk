#include "select_unix_event_queue.h"

#include <modules/event_queue/nm_event_queue.h>

void select_unix_event_queue_init(struct nm_event_queue* eventQueue, struct np_platform* pl)
{
    pl->eqData = eventQueue;
    pl->eq.create_event = &nm_event_queue_create_event;
    pl->eq.destroy_event = &nm_event_queue_destroy_event;
    pl->eq.post = &nm_event_queue_post_event;
    pl->eq.post_maybe_double = &nm_event_queue_post_event_maybe_double;
    pl->eq.cancel = &nm_event_queue_cancel_event;
    pl->eq.create_timed_event = &nm_event_queue_create_timed_event;
    pl->eq.destroy_timed_event = &nm_event_queue_destroy_timed_event;
    pl->eq.post_timed_event = &nm_event_queue_post_timed_event;
    pl->eq.cancel_timed_event = &nm_event_queue_cancel_timed_event;
}
