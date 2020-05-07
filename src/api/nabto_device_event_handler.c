#include "nabto_device_event_handler.h"
#include "nabto_device_defines.h"
#include "nabto_api_future_queue.h"

#include <platform/np_logging.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

void nabto_device_listener_resolve_error_state(struct nabto_device_listener* listener);

void nabto_device_listener_pop_event(struct nabto_device_listener* listener, struct nabto_device_event* ev);

static np_error_code nabto_device_listener_stop_internal(struct nabto_device_listener* listener);

NabtoDeviceListener* NABTO_DEVICE_API nabto_device_listener_new(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_listener* listener = (struct nabto_device_listener*)calloc(1,sizeof(struct nabto_device_listener));
    listener->isInitialized = false;
    listener->type = NABTO_DEVICE_LISTENER_TYPE_NONE;
    listener->dev = dev;

    np_list_append(&dev->listeners, &listener->listenersItem, listener);

    nabto_device_threads_mutex_lock(dev->eventMutex);

    //add_listener_to_device(dev, listener);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return (NabtoDeviceListener*)listener;
}

np_error_code nabto_device_listener_init(struct nabto_device_context* dev,
                                         struct nabto_device_listener* listener,
                                         enum nabto_device_listener_type type,
                                         nabto_device_listener_resolve_event cb,
                                         void* listenerData)
{
    listener->dev = dev;
    listener->cb = cb;
    listener->listenerData = listenerData;
    listener->sentinel.next = &listener->sentinel;
    listener->sentinel.prev = &listener->sentinel;
    listener->ec = NABTO_EC_OK;
    listener->type = type;
    listener->isInitialized = true;
    return NABTO_EC_OK;
}

np_error_code nabto_device_listener_add_event(struct nabto_device_listener* listener, void* data)
{
    if (!listener->isInitialized) {
        return NABTO_EC_INVALID_STATE;
    }
    if (listener->ec != NABTO_EC_OK) {
        return listener->ec;
    }
    struct nabto_device_event* ev = (struct nabto_device_event*)calloc(1,sizeof(struct nabto_device_event));
    if (ev == NULL) {
        listener->ec = NABTO_EC_OUT_OF_MEMORY;
        nabto_device_listener_resolve_error_state(listener);
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ev->data = data;
    struct nabto_device_event* before = listener->sentinel.prev;
    struct nabto_device_event* after = &listener->sentinel;
    before->next = ev;
    ev->next = after;
    after->prev = ev;
    ev->prev = before;
    nabto_device_listener_try_resolve(listener);
    return NABTO_EC_OK;
}

void NABTO_DEVICE_API nabto_device_listener_free(NabtoDeviceListener* deviceListener)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_context* dev = listener->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    np_list_erase_item(&listener->listenersItem);

    free(listener);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

void* nabto_device_listener_get_listener_data(struct nabto_device_listener* listener)
{
    if (!listener->isInitialized) {
        return NULL;
    }
    return listener->listenerData;
}

enum nabto_device_listener_type nabto_device_listener_get_type(struct nabto_device_listener* listener)
{
    return listener->type;
}

np_error_code nabto_device_listener_init_future(struct nabto_device_listener* listener, struct nabto_device_future* future)
{
    if (!listener->isInitialized) {
        return NABTO_EC_INVALID_STATE;
    }
    if (listener->ec != NABTO_EC_OK) {
        return listener->ec;
    }
    if (listener->fut != NULL) {
        return NABTO_EC_OPERATION_IN_PROGRESS;
    }

    listener->fut = future;
    return NABTO_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_listener_stop(NabtoDeviceListener* deviceListener)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    np_error_code ec;
    nabto_device_threads_mutex_lock(listener->dev->eventMutex);
    ec = nabto_device_listener_stop_internal(listener);
    nabto_device_threads_mutex_unlock(listener->dev->eventMutex);

    return nabto_device_error_core_to_api(ec);
}


void nabto_device_listener_set_error_code(struct nabto_device_listener* listener, np_error_code ec)
{
    if (!listener->isInitialized) {
        NABTO_LOG_ERROR(LOG, "Tried to set error code on uninitialized listener");
        return;
    }
    listener->ec = ec;
    nabto_device_listener_resolve_error_state(listener);
}

np_error_code nabto_device_listener_get_status(struct nabto_device_listener* listener)
{
    return listener->ec;
}

void nabto_device_listener_stop_all(struct nabto_device_context* dev)
{
    struct np_list_iterator iterator;
    for (np_list_front(&dev->listeners, &iterator);
         np_list_end(&iterator) == false;
         np_list_next(&iterator))
    {
        struct nabto_device_listener* listener = np_list_get_element(&iterator);
        nabto_device_listener_stop_internal(listener);
    }
}



/********************
 * Helper Functions *
 ********************/

np_error_code nabto_device_listener_stop_internal(struct nabto_device_listener* listener)
{
    if (!listener->isInitialized) {
        return NABTO_EC_INVALID_STATE;
    }
    if (listener->ec == NABTO_EC_OK) {
        nabto_device_listener_set_error_code(listener, NABTO_EC_STOPPED);
        return NABTO_EC_STOPPED;
    }
    return listener->ec;
}


void nabto_device_listener_try_resolve(struct nabto_device_listener* listener)
{
    if (listener->fut && listener->sentinel.next != &listener->sentinel) {
        np_error_code ec = NABTO_DEVICE_EC_UNKNOWN;
        if (listener->cb) {
            ec = listener->cb(NABTO_EC_OK, listener->fut, listener->sentinel.next->data, listener->listenerData);
        }
        nabto_device_future_resolve(listener->fut, nabto_device_error_core_to_api(ec));
        listener->fut = NULL;
        nabto_device_listener_pop_event(listener, listener->sentinel.next);
    }
}

void nabto_device_listener_resolve_error_state(struct nabto_device_listener* listener)
{
    np_error_code ec = listener->ec;
    if (listener->ec == NABTO_EC_ABORTED) {
        // On aborted, we stop all events first, then resolve with ABORTED
        ec = NABTO_EC_STOPPED;
    }
    while (listener->sentinel.next != &listener->sentinel) {
        if (listener->cb) {
            listener->cb(ec, NULL, listener->sentinel.next->data, listener->listenerData);
        }
        nabto_device_listener_pop_event(listener, listener->sentinel.next);
    }
    if (listener->fut) {
        nabto_device_future_resolve(listener->fut, nabto_device_error_core_to_api(listener->ec));
        listener->fut = NULL;
    }
    if (listener->cb) {
        listener->cb(NABTO_EC_ABORTED, NULL, NULL, listener->listenerData);
    }
    listener->cb = NULL;
}

void nabto_device_listener_pop_event(struct nabto_device_listener* listener, struct nabto_device_event* ev)
{
    struct nabto_device_event* before = ev->prev;
    struct nabto_device_event* after = ev->next;
    before->next = after;
    after->prev = before;
    free(ev);
}
