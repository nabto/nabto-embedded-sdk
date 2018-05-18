#ifndef NP_EVENT_QUEUE_H
#define NP_EVENT_QUEUE_H


#include <platform/np_error_code.h>
#include <platform/np_timestamp.h>

#include <platform/np_types.h>

/**
 * Event Queue.
 *
 * The event queue implements queing functionality for events. Two
 * types of events exists asynchronous events and timed asynchronous
 * events.
 */

struct np_platform;

typedef void (*np_event_callback)(void* data);
typedef void (*np_timed_event_callback)(const np_error_code ec, void* data);

/**
 * The event is owned by the one who is posting the event. This way we
 * do not need to allocate space for a large queue inside this module.
 */
struct np_event;
struct np_event {
    // Reference to next element in the queue
    struct np_event* next;
    np_event_callback cb;
    void* data;
};

struct np_timed_event {
    // Reference to the previous element in the priority queue
    struct np_timed_event* next;
    np_timestamp timestamp;
    np_timed_event_callback cb;
    void* data;    
};

struct np_event_list {
    struct np_event* head;
    struct np_event* tail;
};

struct np_timed_event_list {
    struct np_timed_event* head;
};

struct np_event_queue {
    // Private data for the event module
    struct np_event_list events;

    // Private data for the timed events module
    struct np_timed_event_list timedEvents;
};

bool np_event_queue_has_ready_event(struct np_platform* pl);
/**
 * Enqueue an event to the event queue.
 */
void np_event_queue_post(struct np_platform* pl, struct np_event* event, np_event_callback cb, void* data);

void np_event_queue_post_timed_event(struct np_platform* pl, struct np_timed_event* event, uint32_t milliseconds, np_timed_event_callback cb, void* data);

/**
 * execute a single event on the event queue, if empty execute ready event from timed event queue
 */
void np_event_queue_execute_one(struct np_platform* pl);

/**
 * execute all ready events on both event queues
 */
void np_event_queue_execute_all(struct np_platform* pl);

/**
 * execute a single event on the event queue
 */
void np_event_queue_poll_one(struct np_platform* pl);

void np_event_queue_poll_one_timed_event(struct np_platform* pl);

/**
 * Return true iff there are no more events ready in the queue to be
 * executed,
 */
bool np_event_queue_is_event_queue_empty(struct np_platform* pl);

bool np_event_queue_has_timed_event(struct np_platform* pl);

bool np_event_queue_has_ready_timed_event(struct np_platform* pl);

void np_event_queue_cancel_timed_event(struct np_platform* pl, struct np_timed_event* ev);

/**
 * Return the time in milliseconds until the next timed event is due,
 * returns 0 if np_event_queue_has_timed_event returns false.
 */
uint32_t np_event_queue_next_timed_event_occurance(struct np_platform* pl);


#endif
