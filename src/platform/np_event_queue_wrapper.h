#ifndef _NP_EVENT_QUEUE_WRAPPER_H_
#define _NP_EVENT_QUEUE_WRAPPER_H_

#include "interfaces/np_event_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Wrapper functions which call the platform adapter functions, see np_event_queue.h for help.
 */

/**
 * Create a new event.
 */
np_error_code np_event_queue_create_event(struct np_event_queue* eq, np_event_callback cb, void* data, struct np_event** event);

/**
 * Destroy an event.
 */
void np_event_queue_destroy_event(struct np_event_queue* eq, struct np_event* event);


/**
 * Enqueue an event to the event queue.
 */
void np_event_queue_post(struct np_event_queue* eq, struct np_event* event);

/**
 * Enqueue an event which maybe already is in the queue. If it is on
 * the queue it is not requeued. These events needs to be initialized with np_event_queue_init_event
 */
void np_event_queue_post_maybe_double(struct np_event_queue* eq, struct np_event* event);

void np_event_queue_post_timed_event(struct np_event_queue* eq, struct np_event* event, uint32_t milliseconds);

void np_event_queue_cancel_event(struct np_event_queue* eq, struct np_event* ev);

#ifdef __cplusplus
} //extern "C"
#endif

#endif
