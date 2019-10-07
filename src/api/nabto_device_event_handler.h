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
 * nabto_device_event_add_event has been called)
 * This is called with ec:
 *      NABTO_EC_OK when future should be resolved
 *      NABTO_EC_OUT_OF_MEMORY if new event could not be allocated
 *      NABTO_EC_ABORTED if handler was freed
 * if ec != NABTO_EC_OK then future = NULL
 */
typedef void (*nabto_device_event_handler_resolve_event)(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* handlerData);

struct nabto_device_event {
    struct nabto_device_event* next;
    struct nabto_device_event* prev;
    void* data;
};

struct nabto_device_event_handler {
    struct nabto_device_context* dev;
    struct nabto_device_event sentinel;
    nabto_device_event_handler_resolve_event cb;
    void* handlerData;
    struct nabto_device_future* fut;
    np_error_code ec;
};

struct nabto_device_event_handler* nabto_device_event_handler_new(struct nabto_device_context* dev,
                                                                  nabto_device_event_handler_resolve_event cb,
                                                                  void* handlerData);
np_error_code nabto_device_event_handler_add_event(struct nabto_device_event_handler* handler, void* eventData);
void nabto_device_event_handler_set_error_code(struct nabto_device_event_handler* handler, np_error_code ec);

#ifdef __cplusplus
} //extern "C"
#endif

#endif // NABTO_DEVICE_EVENT_HANDLER_H
