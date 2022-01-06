#include "nabto_device_event_handler.h"
#include "nabto_device_defines.h"
#include <api/nabto_device_error.h>

#include <platform/np_logging.h>
#include <platform/np_allocator.h>

#define LOG NABTO_LOG_MODULE_API

void nabto_device_listener_resolve_error_state(struct nabto_device_listener* listener);

void nabto_device_listener_pop_event(struct nabto_device_listener* listener, struct nabto_device_event* ev);

static np_error_code nabto_device_listener_stop_internal(struct nabto_device_listener* listener);

NabtoDeviceListener* NABTO_DEVICE_API nabto_device_listener_new(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_listener* listener = (struct nabto_device_listener*)np_calloc(1,sizeof(struct nabto_device_listener));
    listener->isInitialized = false;
    listener->type = NABTO_DEVICE_LISTENER_TYPE_NONE;
    listener->dev = dev;
    listener->genericFutureResolverData = NULL;

    nn_llist_append(&dev->listeners, &listener->listenersItem, listener);

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

    nn_llist_init(&listener->eventsList);
    listener->ec = NABTO_EC_OK;
    listener->type = type;
    listener->isInitialized = true;
    return NABTO_EC_OK;
}

np_error_code nabto_device_listener_add_event(struct nabto_device_listener* listener, struct nn_llist_node* eventListNode, void* data)
{
    if (!listener->isInitialized) {
        return NABTO_EC_INVALID_STATE;
    }
    if (listener->ec != NABTO_EC_OK) {
        return listener->ec;
    }

    nn_llist_append(&listener->eventsList, eventListNode, data);
    nabto_device_listener_try_resolve(listener);
    return NABTO_EC_OK;
}

void NABTO_DEVICE_API nabto_device_listener_free(NabtoDeviceListener* deviceListener)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_context* dev = listener->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    nn_llist_erase_node(&listener->listenersItem);

    np_free(listener);
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
    struct nn_llist_iterator it = nn_llist_begin(&dev->listeners);
    while(!nn_llist_is_end(&it))
    {
        struct nabto_device_listener* l = nn_llist_get_item(&it);
        nabto_device_threads_mutex_lock(l->dev->eventMutex);
        nabto_device_listener_stop_internal(l);
        nn_llist_next(&it);
        nabto_device_threads_mutex_unlock(l->dev->eventMutex);
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
    // try to resolve the front item

    if (listener->fut && !nn_llist_empty(&listener->eventsList)) {
        np_error_code ec = NABTO_EC_UNKNOWN;
        struct nn_llist_iterator it = nn_llist_begin(&listener->eventsList);
        void* item = nn_llist_get_item(&it);
        nn_llist_erase(&it);

        if (listener->genericFutureResolverData != NULL) {
            *listener->genericFutureResolverData = item;
        }
        if (listener->cb) {
            ec = listener->cb(NABTO_EC_OK, listener->fut, item, listener->listenerData);
        }
        nabto_device_future_resolve(listener->fut, nabto_device_error_core_to_api(ec));
        listener->fut = NULL;
    }
}

void nabto_device_listener_resolve_error_state(struct nabto_device_listener* listener)
{
    np_error_code ec = listener->ec;
    if (listener->ec == NABTO_EC_ABORTED) {
        // On aborted, we stop all events first, then resolve with ABORTED
        ec = NABTO_EC_STOPPED;
    }

    while (!nn_llist_empty(&listener->eventsList)) {
        struct nn_llist_iterator it = nn_llist_begin(&listener->eventsList);
        void* item = nn_llist_get_item(&it);
        nn_llist_erase(&it);
        if (listener->cb) {
            listener->cb(ec, NULL, item, listener->listenerData);
        }

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
