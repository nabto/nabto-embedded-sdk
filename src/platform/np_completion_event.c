#include "np_completion_event.h"

#include <platform/np_event_queue_wrapper.h>
#include <platform/np_platform.h>


#include <string.h>

static void resolve_event_callback(void* userData);

np_error_code np_completion_event_init(struct np_event_queue* eq, struct np_completion_event* completionEvent, np_completion_event_callback cb, void* userData)
{
    memset(completionEvent, 0, sizeof(struct np_completion_event));
    completionEvent->cb = cb;
    completionEvent->userData = userData;
    completionEvent->eq = *eq;

    np_error_code ec = np_event_queue_create_event(eq, &resolve_event_callback, completionEvent, &completionEvent->event);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    completionEvent->initialized = true;
    return NABTO_EC_OK;

}

void np_completion_event_deinit(struct np_completion_event* completionEvent)
{
    if (completionEvent->initialized) {
        np_event_queue_destroy_event(&completionEvent->eq, completionEvent->event);
        completionEvent->initialized = false;
    }
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
