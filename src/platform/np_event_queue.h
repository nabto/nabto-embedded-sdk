#ifndef NP_EVENT_QUEUE_H
#define NP_EVENT_QUEUE_H


#include <platform/np_error_code.h>
#include <platform/np_timestamp.h>

#include <platform/np_types.h>

#include <event.h>

#ifdef __cplusplus
extern "C" {
#endif

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

typedef void (*np_event_queue_executor_notify)(void* data);

/**
 * The event is owned by the one who is posting the event. This way we
 * do not need to allocate space for a large queue inside this module.
 */
struct np_event;
struct np_event {
    struct np_platform* pl;
    // Reference to next element in the queue
    np_event_callback cb;
    void* data;
    struct event event;
};

struct np_timed_event {
    struct np_platform* pl;
    // Reference to the previous element in the priority queue
    np_timed_event_callback cb;
    void* data;
    struct event event;
};

struct np_event_queue {
    /**
     * Init an event
     *
     * @param pl  The platform.
     * @param event  The event to initialize.
     * @param cb  The callback to execute when executed.
     * @param data  The callback user data.
     */
    void (*init_event)(struct np_platform* pl, struct np_event* event, np_event_callback cb, void* data);

    /**
     * Post the event to the event queue
     *
     * @param event
     */
    bool (*post)(struct np_event* event);

    /**
     * Post an event which has the chance of being double
     * posted. i.e. be added to the event queue before it has been
     * executed.
     *
     * @param event  The event.
     */
    void (*post_maybe_double)(struct np_event* event);

    /**
     * Cancel an event
     *
     * @param event  The event.
     */
    void (*cancel)(struct np_event* event);


    /**
     * Init a timed event
     *
     * @param pl  The platform.
     * @param event  The timed event to initialize.
     * @param cb  The callback to call when the timed event is executed.
     * @param data  The user data for the callback.
     */
    void (*init_timed_event)(struct np_platform* pl, struct np_timed_event* event, np_timed_event_callback cb, void* data);

    /**
     * Post a timed event to the event queue
     *
     * @param event  The event.
     * @param milliseconds  The amount of milliseconds into the future until the event is executed.
     */
    void (*post_timed_event)(struct np_timed_event* event, uint32_t milliseconds);


    /**
     * Cancel a timed event
     *
     * @param timedEvent  The timed event.
     */
    void (*cancel_timed_event)(struct np_timed_event* timedEvent);
};

void np_event_queue_init_event(struct np_platform* pl, struct np_event* event, np_event_callback cb, void* data);

/**
 * Enqueue an event to the event queue.
 */
bool np_event_queue_post(struct np_event* event);

/**
 * Enqueue an event which maybe already is in the queue. If it is on
 * the queue it is not requeued. These events needs to be initialized with np_event_queue_init_event
 */
void np_event_queue_post_maybe_double(struct np_event* event);

void np_event_queue_init_timed_event(struct np_platform* pl, struct np_timed_event* event, np_timed_event_callback cb, void* data);

void np_event_queue_post_timed_event(struct np_timed_event* event, uint32_t milliseconds);

void np_event_queue_cancel_timed_event(struct np_timed_event* ev);

void np_event_queue_cancel_event(struct np_event* ev);


#ifdef __cplusplus
} //extern "C"
#endif

#endif
