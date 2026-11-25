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
        if (completionEvent->armed) {
            np_lifetime_violation("completion event deinitialized while its operation is outstanding");
            // The owner reference is not dropped, it could free the memory
            // this event is in. The owner is leaked instead.
            completionEvent->armed = false;
        }
        np_event_queue_destroy_event(&completionEvent->eq, completionEvent->event);
        completionEvent->initialized = false;
    }
}

void np_completion_event_reinit(struct np_completion_event* completionEvent, np_completion_event_callback cb, void* userData)
{
    if (completionEvent->armed) {
        np_lifetime_violation("completion event reinitialized while its operation is outstanding");
    }
    completionEvent->cb = cb;
    completionEvent->userData = userData;
}

void np_completion_event_set_owner(struct np_completion_event* completionEvent, struct np_ref* owner)
{
    if (completionEvent->armed) {
        np_lifetime_violation("owner changed on an armed completion event");
        return;
    }
    completionEvent->owner = owner;
}

void np_completion_event_arm(struct np_completion_event* completionEvent)
{
    if (completionEvent->armed) {
        np_lifetime_violation("completion event armed while its operation is outstanding");
        return;
    }
    completionEvent->armed = true;
    if (completionEvent->owner != NULL) {
        np_ref_get(completionEvent->owner);
    }
}

void np_completion_event_disarm(struct np_completion_event* completionEvent)
{
    if (!completionEvent->armed) {
        np_lifetime_violation("completion event disarmed but it is not armed");
        return;
    }
    completionEvent->armed = false;
    if (completionEvent->owner != NULL) {
        np_ref_put(completionEvent->owner);
    }
}

bool np_completion_event_is_armed(const struct np_completion_event* completionEvent)
{
    return completionEvent->armed;
}

void np_completion_event_resolve(struct np_completion_event* completionEvent, np_error_code ec)
{
    completionEvent->ec = ec;
    np_event_queue_post(&completionEvent->eq, completionEvent->event);
}

void resolve_event_callback(void* userData)
{
    struct np_completion_event* completionEvent = userData;
    if (!completionEvent->armed) {
        np_lifetime_violation("completion event resolved but it is not armed, it is resolved twice or it was never armed");
        completionEvent->cb(completionEvent->ec, completionEvent->userData);
        return;
    }
    // Disarm before the callback, so the callback can start a new operation
    // with the same event. The owner reference is held until the callback
    // has returned.
    completionEvent->armed = false;
    struct np_ref* owner = completionEvent->owner;
    completionEvent->cb(completionEvent->ec, completionEvent->userData);
    if (owner != NULL) {
        np_ref_put(owner);
    }
}
