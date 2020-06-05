#ifndef NP_EVENT_QUEUE_H
#define NP_EVENT_QUEUE_H


#include <platform/np_error_code.h>

#include <platform/np_types.h>

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

typedef void (*np_event_callback)(void* data);
typedef void (*np_timed_event_callback)(const np_error_code ec, void* data);

// opaque pointers
struct np_event;
struct np_timed_event;


struct np_event_queue_functions;

struct np_event_queue {
    const struct np_event_queue_functions* vptr;
    // Pointer to implementation specific data.
    void* data;
};

struct np_event_queue_functions {
    /**
     * Create a new event
     *
     * @param obj  The event queue object.
     * @param cb  The callback to associate with the event.
     * @param cbData  The data to associate with the callback.
     * @param event  The resulting event.
     * @return NABTO_EC_OK  iff the event is created.
     */
    np_error_code (*create_event)(struct np_event_queue* obj, np_event_callback cb, void* cbData, struct np_event** event);

    /**
     * Destroy an event.
     * @param event  The event.
     */
    void (*destroy_event)(struct np_event* event);

    /**
     * Post the event to the event queue
     *
     * @param event
     */
    void (*post)(struct np_event* event);

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
     * Create a timed event
     *
     * @param obj  The event queue object.
     * @param cb  The callback to call when the timed event is executed.
     * @param cbData  The user data for the callback.
     * @param event  The resulting timed event.
     * @return NABTO_EC_OK  iff the timed event was created.
     */
    np_error_code (*create_timed_event)(struct np_event_queue* obj, np_timed_event_callback cb, void* cbData, struct np_timed_event** event);

    /**
     * Destroy a timed event
     *
     * @param event  The timed event
     */
    void (*destroy_timed_event)(struct np_timed_event* event);

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

#ifdef __cplusplus
} //extern "C"
#endif

#endif
