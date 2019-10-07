#ifndef NABTO_DEVICE_EVENT_HANDLER_H
#define NABTO_DEVICE_EVENT_HANDLER_H

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
 * Function called by the event handler when an event is ready to be
 * resolved, once the call returns, the event handler will resolve the
 * future with whatever code is set during the call. The event handler
 * deems a future ready to be resolved if
 * nabto_device_event_handler_create_future has been called, and the
 * sentinel does not point to itself. (ie.
 * nabto_device_event_add_event has been called) If the handler goes
 * into an error state, this function is called with the error for
 * each event in the queue. Once no more events are left, this
 * function is called once with error code NABTO_EC_STOPPED to signal
 * that the event handler has been stopped and no further actions will
 * be made on provided references and it is okay to cleanup any
 * remaining resources.
 *
 * This is called with ec:
 *      NABTO_EC_OK when future should be resolved
 *      NABTO_EC_OUT_OF_MEMORY if new event could not be allocated
 *      NABTO_EC_ABORTED if handler was freed
 *      NABTO_EC_STOPPED if all events are resolved, and handler was freed
 * if ec != NABTO_EC_OK then future = NULL
 */
typedef void (*nabto_device_event_handler_resolve_event)(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* handlerData);

struct nabto_device_event_handler;

/**
 * allocate new event handler
 *
 * @param dev          Device
 * @param cb           Callback called as detailed above
 * @param handlerData  Void data included in every callback
 * @return allocated event handler or NULL on errors
 */
struct nabto_device_event_handler* nabto_device_event_handler_new(struct nabto_device_context* dev,
                                                                  nabto_device_event_handler_resolve_event cb,
                                                                  void* handlerData);

/**
 * Add event to the event handler
 *
 * @param handler   The handler
 * @param eventData Void data included in the callback when event resolved. Events are always resolved exactly once.
 * @return NABTO_EC_OK if event was accepted
 *         NABTO_EC_OUT_OF_MEMORY if event allocation failed
 *         Whatever error state the handler is in eg. by nabto_device_event_handler_set_error_code
 */
np_error_code nabto_device_event_handler_add_event(struct nabto_device_event_handler* handler, void* eventData);

/**
 * Set error code on event handler. Putting the handler into an error
 * state where all queued events are resolved with the provided error
 * code. If a future is created it will also be resolved with the
 * error code.
 *
 * @param handler  The handler
 * @param ec       The error code
 */
void nabto_device_event_handler_set_error_code(struct nabto_device_event_handler* handler, np_error_code ec);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NABTO_DEVICE_EVENT_HANDLER_H
