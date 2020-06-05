#include "np_completion_event.h"

#include <platform/np_event_queue_wrapper.h>

#include <stdlib.h>
#include <string.h>

static void resolve_event_callback(void* userData);

np_error_code np_completion_event_init(struct np_platform* pl, struct np_completion_event* completionEvent, np_completion_event_callback cb, void* userData)
{
    memset(completionEvent, 0, sizeof(struct np_completion_event));
    completionEvent->cb = cb;
    completionEvent->userData = userData;
    completionEvent->pl = pl;

    return np_event_queue_create_event(completionEvent->pl, &resolve_event_callback, completionEvent, &completionEvent->event);
}

void np_completion_event_deinit(struct np_completion_event* completionEvent)
{
    np_event_queue_destroy_event(completionEvent->pl, completionEvent->event);
}

void np_completion_event_reinit(struct np_completion_event* completionEvent, np_completion_event_callback cb, void* userData)
{
    completionEvent->cb = cb;
    completionEvent->userData = userData;
}



void np_completion_event_resolve(struct np_completion_event* completionEvent, np_error_code ec)
{
    completionEvent->ec = ec;
    np_event_queue_post(completionEvent->pl, completionEvent->event);
}


void resolve_event_callback(void* userData)
{
    struct np_completion_event* completionEvent = userData;
    completionEvent->cb(completionEvent->ec, completionEvent->userData);
}
