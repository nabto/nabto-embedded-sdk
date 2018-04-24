#ifndef NABTO_PLATFORM_H
#define NABTO_PLATFORM_H

#include <platform/types.h>
#include <platform/error_code.h>
#include <platform/timestamp.h>

/**
 * The nabto platform is an object containing references to all the
 * different parts the system consists of.
 */

typedef void (*nabto_platform_event_callback)(void* data);
typedef void (*nabto_platform_timed_event_callback)(const nabto_error_code ec, void* data);

struct nabto_platform_event;

/**
 * The event is owned by the one who is posting the event. This way we
 * do not need to allocate space for a large queue inside this module.
 */
struct nabto_platform_event {
    // Reference to next element in the queue
    struct nabto_platform_event* next;
    nabto_platform_event_callback cb;
    void* data;
};

struct nabto_platform_timed_event {
    // Reference to the previous element in the priority queue
    struct nabto_platform_timed_event* next;
    nabto_timestamp timestamp;
    nabto_platform_timed_event_callback cb;
    void* data;    
};

static struct nabto_platform_timed_event nabtoPlatformTimedEventLast;


struct nabto_platform_event_queue {
    struct nabto_platform_event* head;
    struct nabto_platform_event* tail;
};

struct nabto_platform_timed_event_queue {
    struct nabto_platform_timed_event* head;
};

/**
 * The platform is the main entry point, it includes references and
 * data for all relevant platform functions which can be called from
 * the core.
 */
    
struct nabto_platform {
    // Timestamp module
    struct nabto_timestamp_module ts;
    
    // Private data for the event module
    struct nabto_platform_event_queue events;

    // Private data for the timed events module
    struct nabto_platform_timed_event_queue timedEvents;
};

/**
 * Initialize the platform structure.
 */
void nabto_platform_init(struct nabto_platform* pl);

/**
 * Enqueue an event to the event queue.
 */
void nabto_platform_post(struct nabto_platform* pl, struct nabto_platform_event* event, nabto_platform_event_callback cb, void* data);

void nabto_platform_post_timed_event(struct nabto_platform* pl, struct nabto_platform_timed_event* event, uint32_t milliseconds, nabto_platform_timed_event_callback cb, void* data);

/**
 * execute a single event on the event queue
 */
void nabto_platform_poll_one(struct nabto_platform* pl);

void nabto_platform_poll_one_timed_event(struct nabto_platform* pl);

/**
 * Return true iff there are no more events ready in the queue to be
 * executed,
 */
bool nabto_platform_is_event_queue_empty(struct nabto_platform* pl);

bool nabto_platform_has_timed_event(struct nabto_platform* pl);

#endif
