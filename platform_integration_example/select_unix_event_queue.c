#include "select_unix_event_queue.h"

void select_unix_event_queue_init(struct select_unix_platform* platform, struct np_platform* pl)
{
    pl->eqData = &platform->eventQueue;
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
