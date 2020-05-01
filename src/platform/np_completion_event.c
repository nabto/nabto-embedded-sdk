#include "np_completion_event.h"

#include <stdlib.h>
#include <string.h>

static void resolve_event_callback(void* userData);

void np_completion_event_init(struct np_platform* pl, struct np_completion_event* completionEvent, np_completion_event_callback cb, void* userData)
{
    memset(completionEvent, 0, sizeof(struct np_completion_event));
    completionEvent->cb = cb;
    completionEvent->userData = userData;
    completionEvent->pl = pl;
}

void np_completion_event_resolve(struct np_completion_event* completionEvent, np_error_code ec)
{
    completionEvent->ec = ec;
    np_event_queue_create_event(completionEvent->pl, &resolve_event_callback, completionEvent, &completionEvent->event);
    np_event_queue_post(completionEvent->pl, &completionEvent->event);
}


void resolve_event_callback(void* userData)
{
    struct np_completion_event* completionEvent = userData;
    completionEvent->cb(completionEvent->ec, completionEvent->userData);
}
