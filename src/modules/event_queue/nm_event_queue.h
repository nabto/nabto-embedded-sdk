#ifndef _NM_EVENT_QUEUE_H_
#define _NM_EVENT_QUEUE_H_

#include <platform/np_platform.h>
#include <nn/llist.h>

struct nm_event_queue {
    struct nn_llist events;
    struct nn_llist timedEvents;
};


struct nm_event_queue_event {
    np_event_callback cb;
    void* data;
    struct nn_llist_node eventsNode;
    uint32_t expireTimestamp;

};

void nm_event_queue_init(struct nm_event_queue* queue);

// see np_event_queue for documentation on the following functions.
void nm_event_queue_event_init(struct nm_event_queue_event* event, np_event_callback cb, void* data);
void nm_event_queue_event_deinit(struct nm_event_queue_event* event);

void nm_event_queue_post_event(struct nm_event_queue* queue, struct nm_event_queue_event* event);
bool nm_event_queue_post_event_maybe_double(struct nm_event_queue* queue, struct nm_event_queue_event* event);
void nm_event_queue_cancel_event(struct nm_event_queue_event* event);

void nm_event_queue_post_timed_event(struct nm_event_queue* queue, struct nm_event_queue_event* event, uint32_t milliseconds);


/**
 * take a single event from the queue if an event exits.
 *
 * @return true iff an event is returned.
 */
bool nm_event_queue_take_event(struct nm_event_queue* queue, struct nm_event_queue_event** event);

/**
 * take a single timed event from the event queue if a timed event exists and ready to be run.
 *
 * @return true iff a timed event is returned.
 */
bool nm_event_queue_take_timed_event(struct nm_event_queue* queue, uint32_t now, struct nm_event_queue_event** event);

/**
 * Get the timestamp of the next event on the event queue.
 *
 * @return true iff an event exists and its assoicated timestamp is
 * copied to nextEvent
 */
bool nm_event_queue_next_timed_event(struct nm_event_queue* queue, uint32_t* nextEvent);

#endif
