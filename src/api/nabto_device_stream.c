#include "nabto_device_stream.h"
#include "nabto_device_future.h"
#include "nabto_device_event_handler.h"

#include <api/nabto_device_defines.h>
#include <api/nabto_device_error.h>
#include <platform/np_logging.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

struct nabto_device_stream_listener_context {
    struct nabto_device_context* device;
    struct nabto_device_listener* listener;
    struct nc_stream_listener coreListener;
    NabtoDeviceStream** stream;
};

/*******************************************
 * Streaming Api
 *******************************************/

NabtoDeviceError NABTO_DEVICE_API nabto_device_stream_init_listener(NabtoDevice* device, NabtoDeviceListener* deviceListener, uint32_t type)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_stream_listener_context* listenerContext = calloc(1, sizeof(struct nabto_device_stream_listener_context));
    if (listenerContext == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec  = nabto_device_listener_init(dev, listener, NABTO_DEVICE_LISTENER_TYPE_STREAMS, &nabto_device_stream_listener_callback, listenerContext);
    if (ec) {
        free(listenerContext);
        return nabto_device_error_core_to_api(ec);
    }
    listenerContext->device = dev;
    listenerContext->listener = listener;
    ec = nc_stream_manager_add_listener(&dev->core.streamManager, &listenerContext->coreListener, type, &nabto_device_stream_core_callback, listenerContext);
    if (ec) {
        free(listenerContext);
        return nabto_device_error_core_to_api(ec);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_stream_init_listener_ephemeral(NabtoDevice* device, NabtoDeviceListener* deviceListener, uint32_t* type)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_stream_listener_context* listenerContext = calloc(1, sizeof(struct nabto_device_stream_listener_context));
    if (listenerContext == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec  = nabto_device_listener_init(dev, listener, NABTO_DEVICE_LISTENER_TYPE_STREAMS, &nabto_device_stream_listener_callback, listenerContext);
    if (ec) {
        free(listenerContext);
        return nabto_device_error_core_to_api(ec);
    }
    listenerContext->device = dev;
    listenerContext->listener = listener;
    ec = nc_stream_manager_add_listener(&dev->core.streamManager, &listenerContext->coreListener, 0, &nabto_device_stream_core_callback, listenerContext);
    if (ec) {
        free(listenerContext);
        return nabto_device_error_core_to_api(ec);
    }
    *type = listenerContext->coreListener.type;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

void NABTO_DEVICE_API nabto_device_listener_new_stream(NabtoDeviceListener* deviceListener, NabtoDeviceFuture* future, NabtoDeviceStream** stream)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_context* dev = listener->dev;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (nabto_device_listener_get_type(listener) != NABTO_DEVICE_LISTENER_TYPE_STREAMS) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_future_resolve(fut, NABTO_DEVICE_EC_INVALID_ARGUMENT);
    }
    np_error_code ec = nabto_device_listener_get_status(listener);
    if (ec != NABTO_EC_OK) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_future_resolve(fut, nabto_device_error_core_to_api(ec));
    }
    struct nabto_device_stream_listener_context* listenerContext = (struct nabto_device_stream_listener_context*)nabto_device_listener_get_listener_data(listener);

    ec = nabto_device_listener_init_future(listener, fut);
    if (ec != NABTO_EC_OK) {
        nabto_device_future_resolve(fut, ec);
    } else {
        *stream = NULL;
        listenerContext->stream = stream;
        nabto_device_listener_try_resolve(listener);
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

void NABTO_DEVICE_API nabto_device_stream_free(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_context* dev = str->dev;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    nc_stream_destroy(str->stream);
    free(str);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

void NABTO_DEVICE_API nabto_device_stream_abort(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_context* dev = str->dev;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    nc_stream_stop(str->stream);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}


void nabto_device_stream_accept_callback(const np_error_code ec, void* userData)
{
    // this callback is from the core, the lock is already taken.
    struct nabto_device_stream* str = userData;
    nabto_device_future_resolve(str->acceptFut, nabto_device_error_core_to_api(ec));
}

void NABTO_DEVICE_API nabto_device_stream_accept(NabtoDeviceStream* stream, NabtoDeviceFuture* future)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    if (str->acceptFut != NULL) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    } else {
        str->acceptFut = fut;
        np_error_code ec = nc_stream_async_accept(str->stream, nabto_device_stream_accept_callback, str);
        if (ec != NABTO_EC_OK) {
            nabto_device_future_resolve(fut, nabto_device_error_core_to_api(ec));
        }
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
}

NabtoDeviceConnectionRef NABTO_DEVICE_API nabto_device_stream_get_connection_ref(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;

    NabtoDeviceConnectionRef ref;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    ref = str->stream->connectionRef;

    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return ref;
}

void nabto_device_stream_read_callback(const np_error_code ec, void* userData)
{
    // this callback is from the core, the lock is already taken.
    struct nabto_device_stream* str = userData;

    nabto_device_future_resolve(str->readFut, nabto_device_error_core_to_api(ec));
    str->readFut = NULL;
}

void NABTO_DEVICE_API nabto_device_stream_read_all(NabtoDeviceStream* stream,
                                                   NabtoDeviceFuture* future,
                                                   void* buffer, size_t bufferLength,
                                                   size_t* readLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    if (str->readFut != NULL) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    } else {
        str->readFut = fut;
        np_error_code ec = nc_stream_async_read_all(str->stream, buffer, bufferLength, readLength, &nabto_device_stream_read_callback, str);
        if (ec) {
            nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
            str->readFut = NULL;
        }
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
}

void NABTO_DEVICE_API nabto_device_stream_read_some(NabtoDeviceStream* stream,
                                                    NabtoDeviceFuture* future,
                                                    void* buffer, size_t bufferLength,
                                                    size_t* readLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    if (str->readFut != NULL) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    } else {
        str->readFut = fut;
        np_error_code ec = nc_stream_async_read_some(str->stream, buffer, bufferLength, readLength, &nabto_device_stream_read_callback, str);
        if (ec) {
            nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
        }
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
}

void nabto_device_stream_write_callback(const np_error_code ec, void* userData)
{
    // this callback is from the core, the lock is already taken.
    struct nabto_device_stream* str = userData;

    nabto_device_future_resolve(str->writeFut, nabto_device_error_core_to_api(ec));
    str->writeFut = NULL;
}

void NABTO_DEVICE_API nabto_device_stream_write(NabtoDeviceStream* stream,
                                                NabtoDeviceFuture* future,
                                                const void* buffer, size_t bufferLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    if (str->writeFut) {
        nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    } else {
        str->writeFut = fut;
        np_error_code ec = nc_stream_async_write(str->stream, buffer, bufferLength, &nabto_device_stream_write_callback, str);
        if (ec) {
            nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
        }
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
}

void nabto_device_stream_close_callback(const np_error_code ec, void* userData)
{
    // this callback is from the core, the lock is already taken.
    struct nabto_device_stream* str = userData;

    NABTO_LOG_INFO(LOG, "stream async close core callback");
    nabto_device_future_resolve(str->closeFut, nabto_device_error_core_to_api(ec));
}

void NABTO_DEVICE_API nabto_device_stream_close(NabtoDeviceStream* stream, NabtoDeviceFuture* future)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    str->closeFut = fut;
    np_error_code ec = nc_stream_async_close(str->stream, &nabto_device_stream_close_callback, str);
    if (ec) {
        nabto_device_future_resolve(fut, nabto_device_error_core_to_api(ec));
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
}

/*******************************************
 * Streaming Api End
 *******************************************/

np_error_code nabto_device_stream_listener_callback(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData)
{
    struct nabto_device_stream_listener_context* listenerContext = (struct nabto_device_stream_listener_context*)listenerData;
    np_error_code retEc;
    if (ec == NABTO_EC_OK) {
        struct nabto_device_stream* str = (struct nabto_device_stream*)eventData;
        if (listenerContext->stream != NULL) {
            retEc = NABTO_EC_OK;
            *listenerContext->stream = (NabtoDeviceStream*)str;
            listenerContext->stream = NULL;
        } else {
            NABTO_LOG_ERROR(LOG, "Tried to resolve new stream future, but stream reference was invalid");
            retEc = NABTO_EC_UNKNOWN;
        }
        // using the stream structure as event structure means it will be freed when user calls stream_free
    } else if (ec == NABTO_EC_ABORTED) {
        nc_stream_manager_remove_listener(&listenerContext->coreListener);
        free(listenerContext);
        retEc = ec;
    } else {
        // In error state streams on the listener queue will not reach the user, so they cant call stream_free
        struct nabto_device_stream* str = (struct nabto_device_stream*)eventData;
        nc_stream_destroy(str->stream);
        free(str);
        retEc = ec;
    }
    return retEc;
}



void nabto_device_stream_core_callback(np_error_code ec, struct nc_stream_context* stream, void* data)
{
    struct nabto_device_stream_listener_context* listenerContext = data;
    struct nabto_device_context* dev = listenerContext->device;
    NABTO_LOG_INFO(LOG, "stream_listener_callback");

    if (ec == NABTO_EC_OK) {
        struct nabto_device_stream* str = calloc(1, sizeof(struct nabto_device_stream));
        if (str == NULL) {
            nc_stream_destroy(stream);
            return;
        }
        str->stream = stream;
        str->dev = dev;
        // using the stream structure directly as listener event, this means we dont free event untill user calls stream_free()
        np_error_code ec = nabto_device_listener_add_event(listenerContext->listener, &str->eventListNode, str);
        if (ec != NABTO_EC_OK) {
            nc_stream_destroy(str->stream);
            free(str);
        }
        return;
    } else {
        nabto_device_listener_set_error_code(listenerContext->listener, ec);
    }
}
