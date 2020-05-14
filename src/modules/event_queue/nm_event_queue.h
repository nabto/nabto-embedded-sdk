#ifndef _NM_EVENT_QUEUE_H_
#define _NM_EVENT_QUEUE_H_

#include <platform/np_platform.h>
#include <nn/llist.h>

struct nm_event_queue {
    struct np_platform* pl;
    struct nn_llist events;
    struct nn_llist timedEvents;
};

void nm_event_queue_init(struct nm_event_queue* queue);

// see np_event_queue for documentation on the following functions.
np_error_code nm_event_queue_create_event(struct np_platform* pl, np_event_callback cb, void* data, struct np_event** event);
void nm_event_queue_destroy_event(struct np_event* event);

void nm_event_queue_post_event(struct np_event* event);
void nm_event_queue_post_event_maybe_double(struct np_event* event);
void nm_event_queue_cancel_event(struct np_event* event);

np_error_code nm_event_queue_create_timed_event(struct np_platform* pl, np_timed_event_callback cb, void* data, struct np_timed_event** event);
void nm_event_queue_destroy_timed_event(struct np_timed_event* event);
void nm_event_queue_post_timed_event(struct np_timed_event* event, uint32_t milliseconds);
void nm_event_queue_cancel_timed_event(struct np_timed_event* event);


/**
 * run a single event on the queue if an event exits.
 *
 * @return true iff an event was executed.
 */
bool nm_event_queue_run_event(struct nm_event_queue* queue);

/**
 * run a single timed event if a timed event exists and ready to be run.
 *
 * @return true iff a timed event was executed
 */
bool nm_event_queue_run_timed_event(struct nm_event_queue* queue, uint32_t now);

/**
 * Get the timestamp of the next event on the event queue.
 *
 * @return true iff an event exists and its assoicated timestamp is
 * copied to nextEvent
 */
bool nm_event_queue_next_timed_event(struct nm_event_queue* queue, uint32_t* nextEvent);

#endif
