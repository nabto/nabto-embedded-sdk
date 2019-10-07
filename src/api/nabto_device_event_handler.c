#include "nabto_device_event_handler.h"
#include "nabto_device_defines.h"
#include "nabto_api_future_queue.h"
#include <stdlib.h>

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

void nabto_device_event_handler_resolve_error_state(struct nabto_device_event_handler* handler);
void nabto_device_event_handler_try_resolve(struct nabto_device_event_handler* handler);
void nabto_device_event_handler_pop_event(struct nabto_device_event_handler* handler, struct nabto_device_event* ev);

struct nabto_device_event_handler* nabto_device_event_handler_new(struct nabto_device_context* dev,
                                                                  nabto_device_event_handler_resolve_event cb,
                                                                  void* handlerData)
{
    struct nabto_device_event_handler* handler = (struct nabto_device_event_handler*)calloc(1,sizeof(struct nabto_device_event_handler));
    if (handler == NULL) {
        return NULL;
    }
    handler->dev = dev;
    handler->cb = cb;
    handler->handlerData = handlerData;
    handler->sentinel.next = &handler->sentinel;
    handler->sentinel.prev = &handler->sentinel;
    handler->ec = NABTO_EC_OK;
    return handler;
}

np_error_code nabto_device_event_handler_add_event(struct nabto_device_event_handler* handler, void* data)
{
    if (handler->ec != NABTO_EC_OK) {
        return handler->ec;
    }
    struct nabto_device_event* ev = (struct nabto_device_event*)calloc(1,sizeof(struct nabto_device_event));
    if (ev == NULL) {
        handler->ec = NABTO_EC_OUT_OF_MEMORY;
        nabto_device_event_handler_resolve_error_state(handler);
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ev->data = data;
    struct nabto_device_event* before = handler->sentinel.prev;
    struct nabto_device_event* after = &handler->sentinel;
    before->next = ev;
    ev->next = after;
    after->prev = ev;
    ev->prev = before;
    nabto_device_event_handler_try_resolve(handler);
    return NABTO_EC_OK;
}

void NABTO_DEVICE_API nabto_device_event_handler_free(NabtoDeviceEventHandler* eventHandler)
{
    struct nabto_device_event_handler* handler = (struct nabto_device_event_handler*)eventHandler;
    handler->ec = NABTO_EC_ABORTED;
    nabto_device_event_handler_resolve_error_state(handler);
    handler->cb(NABTO_EC_STOPPED, NULL, NULL, handler->handlerData);
    free(handler);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_event_handler_create_future(NabtoDeviceEventHandler* eventHandler, NabtoDeviceFuture** future)
{
    struct nabto_device_event_handler* handler = (struct nabto_device_event_handler*)eventHandler;
    if (handler->ec != NABTO_EC_OK) {
        return nabto_device_error_core_to_api(handler->ec);
    }
    handler->fut = nabto_device_future_new(handler->dev);
    *future = (NabtoDeviceFuture*)handler->fut;
    if (handler->fut == NULL) {
        return NABTO_DEVICE_EC_FAILED;
    }
    nabto_device_event_handler_try_resolve(handler);
    return NABTO_DEVICE_EC_OK;
}

void nabto_device_event_handler_set_error_code(struct nabto_device_event_handler* handler, np_error_code ec)
{
    handler->ec = ec;
    nabto_device_event_handler_resolve_error_state(handler);
}


/********************
 * Helper Functions *
 ********************/
void nabto_device_event_handler_try_resolve(struct nabto_device_event_handler* handler)
{
    if (handler->fut && handler->sentinel.next != &handler->sentinel) {
        handler->cb(NABTO_EC_OK, handler->fut, handler->sentinel.next->data, handler->handlerData);
        nabto_api_future_queue_post(&handler->dev->queueHead, handler->fut);
        handler->fut = NULL;
        nabto_device_event_handler_pop_event(handler, handler->sentinel.next);
    }
}

void nabto_device_event_handler_resolve_error_state(struct nabto_device_event_handler* handler)
{
    while (handler->sentinel.next != &handler->sentinel) {
        handler->cb(handler->ec, NULL, handler->sentinel.next->data, handler->handlerData);
        nabto_device_event_handler_pop_event(handler, handler->sentinel.next);
    }
    if (handler->fut) {
        nabto_api_future_set_error_code(handler->fut, nabto_device_error_core_to_api(handler->ec));
        nabto_api_future_queue_post(&handler->dev->queueHead, handler->fut);
    }
}

void nabto_device_event_handler_pop_event(struct nabto_device_event_handler* handler, struct nabto_device_event* ev)
{
    struct nabto_device_event* before = ev->prev;
    struct nabto_device_event* after = ev->next;
    before->next = after;
    after->prev = before;
    free(ev);
}
