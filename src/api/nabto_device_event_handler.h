#ifndef NABTO_DEVICE_LISTENER_H
#define NABTO_DEVICE_LISTENER_H

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <api/nabto_device_future.h>
#include <platform/np_error_code.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nabto_device_context;

struct nabto_device_event;

/**
 * Function called by the listener when an event is ready to be
 * resolved, once the call returns, the listener will resolve the
 * future with whatever code is set during this call. The listener
 * deems a future ready to be resolved if
 * nabto_device_listener_create_future has been called, and the
 * sentinel does not point to itself. (ie.
 * nabto_device_listener_add_event has been called) If the listener
 * goes into an error state, this function is called with the error
 * for each event in the queue. Once no more events are left, this
 * function is called once with error code NABTO_EC_ABORTED to signal
 * that the listener has been aborted and no further actions will be
 * made on provided references and it is okay to cleanup any remaining
 * resources.
 *
 * This is called with ec:
 *      NABTO_EC_OK when future should be resolved
 *      NABTO_EC_OUT_OF_MEMORY if new event could not be allocated
 *      NABTO_EC_ABORTED if listener is completely finished
 *      NABTO_EC_STOPPED if resolving events if the listener was stopped
 * if ec != NABTO_EC_OK then future = NULL
 */
typedef void (*nabto_device_listener_resolve_event)(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData);

enum nabto_device_listener_type {
    NABTO_DEVICE_LISTENER_TYPE_CONNECTION_EVENTS,
    NABTO_DEVICE_LISTENER_TYPE_DEVICE_EVENTS,
    NABTO_DEVICE_LISTENER_TYPE_STREAMS,
    NABTO_DEVICE_LISTENER_TYPE_COAP
};


struct nabto_device_event {
    struct nabto_device_event* next;
    struct nabto_device_event* prev;
    void* data;
};

struct nabto_device_listener {
    struct nabto_device_context* dev;
    struct nabto_device_event sentinel;
    nabto_device_listener_resolve_event cb;
    void* listenerData;
    struct nabto_device_future* fut;
    np_error_code ec;
    enum nabto_device_listener_type type;
};

/**
 * allocate new listener
 *
 * @param dev          Device
 * @param cb           Callback called as detailed above
 * @param listenerData Void data included in every callback
 * @return allocated listener or NULL on errors
 */
struct nabto_device_listener* nabto_device_listener_new(struct nabto_device_context* dev,
                                                        enum nabto_device_listener_type type,
                                                        nabto_device_listener_resolve_event cb,
                                                        void* listenerData);

enum nabto_device_listener_type nabto_device_listener_get_type(struct nabto_device_listener* listener);
np_error_code nabto_device_listener_create_future(struct nabto_device_listener* listener, struct nabto_device_future** future);
np_error_code nabto_device_listener_get_status(struct nabto_device_listener* listener);

void* nabto_device_listener_get_listener_data(struct nabto_device_listener* listener);

/**
 * Add event to the listener
 *
 * @param listener   The listener
 * @param eventData  Void data included in the callback when event resolved. Events are always resolved exactly once.
 * @return NABTO_EC_OK if event was accepted
 *         NABTO_EC_OUT_OF_MEMORY if event allocation failed
 *         Whatever error state the listener is in eg. by nabto_device_listener_set_error_code
 */
np_error_code nabto_device_listener_add_event(struct nabto_device_listener* listener, void* eventData);

/**
 * Set error code on listener. Putting the listener into an error
 * state where all queued events are resolved with the provided error
 * code. If a future is created it will also be resolved with the
 * error code.
 *
 * @param listener  The listener
 * @param ec        The error code
 */
void nabto_device_listener_set_error_code(struct nabto_device_listener* listener, np_error_code ec);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NABTO_DEVICE_LISTENER_H
