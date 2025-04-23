#ifndef NP_COMPLETION_EVENT_H_
#define NP_COMPLETION_EVENT_H_

#include "interfaces/np_event_queue.h"
#include "np_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*np_completion_event_callback)(const np_error_code ec, void* userData);

struct np_completion_event {
    bool initialized;
    struct np_event_queue eq;
    np_completion_event_callback cb;
    void* userData;
    np_error_code ec;
    struct np_event* event;
};

/**
 * Init a completion event.
 *
 * @param pl  The platform.
 * @param completionEvent  The completion event to initialize.
 * @param cb  The callback to call when the completion events is resolved.
 * @param userData  The userData to give to the callback.
 */
np_error_code np_completion_event_init(struct np_event_queue* eq, struct np_completion_event* completionEvent, np_completion_event_callback cb, void* userData);

/**
 * Reinitialize a completion event.
 */
void np_completion_event_reinit(struct np_completion_event* completionEvent, np_completion_event_callback cb, void* userData);

/**
 * Deinitialize a completion event.
 *
 * @param completionEvent  The completionEvent
 */
void np_completion_event_deinit(struct np_completion_event* completionEvent);

/**
 * Resolve a completion event.
 *
 * The completion event is resolved from the internal event queue.
 *
 * @param completionEvent  The completion event to resolve.
 * @param ec  The error code
 */
void np_completion_event_resolve(struct np_completion_event* completionEvent, np_error_code ec);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
