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

// opaque pointers
struct np_event;

struct np_event_queue_functions;

struct np_event_queue {
    const struct np_event_queue_functions* mptr;
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
    np_error_code (*create)(struct np_event_queue* obj, np_event_callback cb, void* cbData, struct np_event** event);

    /**
     * Destroy an event.
     * @param event  The event.
     */
    void (*destroy)(struct np_event* event);

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
     * @return true iff the event is scheduled ie not double posted.
     */
    bool (*post_maybe_double)(struct np_event* event);

    /**
     * Cancel an event, the event will not be executed.
     *
     * Only timed events will be cancelled. Since cancellation of non timed
     * events leads to missing callbacks and invalid program state.
     *
     * @param event  The event.
     */
    void (*cancel)(struct np_event* event);

    /**
     * Post a timed event to the event queue
     *
     * @param event  The event.
     * @param milliseconds  The amount of milliseconds into the future until the event is executed.
     */
    void (*post_timed)(struct np_event* event, uint32_t milliseconds);

    /**
     * Optional Experimental feature. This is needed if
     * NABTO_DEVICE_NO_FUTURE_QUEUE is set.
     *
     * Post an event which should be resolved without taking the core lock for
     * the platform. This is used to resolve callbacks to external code. Eg.
     * When nabto_device_future resolves and a callback is set.
     */
    void (*post_no_core_lock)(struct np_event* event);
};

#ifdef __cplusplus
} //extern "C"
#endif

#endif
