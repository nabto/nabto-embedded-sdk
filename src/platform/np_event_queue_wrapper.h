#ifndef _NP_EVENT_QUEUE_WRAPPER_H_
#define _NP_EVENT_QUEUE_WRAPPER_H_

/**
 * Wrapper functions which call the platform adapter functions, see np_event_queue.h for help.
 */


/**
 * Create a new event.
 */
np_error_code np_event_queue_create_event(struct np_platform* pl, np_event_callback cb, void* data, struct np_event** event);

/**
 * Destroy an event.
 */
void np_event_queue_destroy_event(struct np_platform* pl, struct np_event* event);

/**
 * Create a new timed event
 */
np_error_code np_event_queue_create_timed_event(struct np_platform* pl, np_timed_event_callback cb, void* data, struct np_timed_event** event);

/**
 * Destroy a timed event
 */
void np_event_queue_destroy_timed_event(struct np_platform* pl, struct np_timed_event* event);

/**
 * Enqueue an event to the event queue.
 */
void np_event_queue_post(struct np_platform* pl, struct np_event* event);

/**
 * Enqueue an event which maybe already is in the queue. If it is on
 * the queue it is not requeued. These events needs to be initialized with np_event_queue_init_event
 */
void np_event_queue_post_maybe_double(struct np_platform* pl, struct np_event* event);

void np_event_queue_init_timed_event(struct np_platform* pl, struct np_timed_event* event, np_timed_event_callback cb, void* data);

void np_event_queue_post_timed_event(struct np_platform* pl, struct np_timed_event* event, uint32_t milliseconds);

void np_event_queue_cancel_timed_event(struct np_platform* pl, struct np_timed_event* ev);

void np_event_queue_cancel_event(struct np_platform* pl, struct np_event* ev);

#endif
