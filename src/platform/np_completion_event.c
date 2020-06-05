#include "np_completion_event.h"

#include <platform/np_event_queue_wrapper.h>
#include <platform/np_platform.h>

#include <stdlib.h>
#include <string.h>

static void resolve_event_callback(void* userData);

np_error_code np_completion_event_init(struct np_event_queue* eq, struct np_completion_event* completionEvent, np_completion_event_callback cb, void* userData)
{
    memset(completionEvent, 0, sizeof(struct np_completion_event));
    completionEvent->cb = cb;
    completionEvent->userData = userData;
    completionEvent->eq = *eq;

    return np_event_queue_create_event(eq, &resolve_event_callback, completionEvent, &completionEvent->event);
}

void np_completion_event_deinit(struct np_completion_event* completionEvent)
{
    np_event_queue_destroy_event(&completionEvent->eq, completionEvent->event);
}

void np_completion_event_reinit(struct np_completion_event* completionEvent, np_completion_event_callback cb, void* userData)
{
    completionEvent->cb = cb;
    completionEvent->userData = userData;
}



void np_completion_event_resolve(struct np_completion_event* completionEvent, np_error_code ec)
{
    completionEvent->ec = ec;
    np_event_queue_post(&completionEvent->eq, completionEvent->event);
}


void resolve_event_callback(void* userData)
{
    struct np_completion_event* completionEvent = userData;
    completionEvent->cb(completionEvent->ec, completionEvent->userData);
}
