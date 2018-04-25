#ifndef NABTO_EVENT_QUEUE_H
#define NABTO_EVENT_QUEUE_H


#include <platform/error_code.h>
#include <platform/timestamp.h>

#include <platform/types.h>

/**
 * Event Queue.
 *
 * The event queue implements queing functionality for events. Two
 * types of events exists asynchronous events and timed asynchronous
 * events.
 */

struct nabto_platform;

typedef void (*nabto_event_callback)(void* data);
typedef void (*nabto_timed_event_callback)(const nabto_error_code ec, void* data);

/**
 * The event is owned by the one who is posting the event. This way we
 * do not need to allocate space for a large queue inside this module.
 */
struct nabto_event;
struct nabto_event {
    // Reference to next element in the queue
    struct nabto_event* next;
    nabto_event_callback cb;
    void* data;
};

struct nabto_timed_event {
    // Reference to the previous element in the priority queue
    struct nabto_timed_event* next;
    nabto_timestamp timestamp;
    nabto_timed_event_callback cb;
    void* data;    
};

struct nabto_event_list {
    struct nabto_event* head;
    struct nabto_event* tail;
};

struct nabto_timed_event_list {
    struct nabto_timed_event* head;
};

struct nabto_event_queue {
    // Private data for the event module
    struct nabto_event_list events;

    // Private data for the timed events module
    struct nabto_timed_event_list timedEvents;
};


/**
 * Enqueue an event to the event queue.
 */
void nabto_event_queue_post(struct nabto_platform* pl, struct nabto_event* event, nabto_event_callback cb, void* data);

void nabto_event_queue_post_timed_event(struct nabto_platform* pl, struct nabto_timed_event* event, uint32_t milliseconds, nabto_timed_event_callback cb, void* data);

/**
 * execute a single event on the event queue
 */
void nabto_event_queue_poll_one(struct nabto_platform* pl);

void nabto_event_queue_poll_one_timed_event(struct nabto_platform* pl);

/**
 * Return true iff there are no more events ready in the queue to be
 * executed,
 */
bool nabto_event_queue_is_event_queue_empty(struct nabto_platform* pl);

bool nabto_event_queue_has_timed_event(struct nabto_platform* pl);

bool nabto_event_queue_has_ready_timed_event(struct nabto_platform* pl);



#endif
