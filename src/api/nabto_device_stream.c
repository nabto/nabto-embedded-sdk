#include "nabto_device_stream.h"
#include "nabto_device_future.h"
#include "nabto_device_event_handler.h"

#include <api/nabto_device_defines.h>
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

NabtoDeviceListener* NABTO_DEVICE_API nabto_device_stream_listener_new(NabtoDevice* device, uint32_t type)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_stream_listener_context* listenerContext = calloc(1, sizeof(struct nabto_device_stream_listener_context));
    if (listenerContext == NULL) {
        return NULL;
    }
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_listener* listener = nabto_device_listener_new(dev, NABTO_DEVICE_LISTENER_TYPE_STREAMS, &nabto_device_stream_listener_callback, listenerContext);
    if (listener == NULL) {
        free(listenerContext);
        return NULL;
    }
    listenerContext->device = dev;
    listenerContext->listener = listener;
    np_error_code ec = nc_stream_manager_add_listener(&dev->core.streamManager, &listenerContext->coreListener, type, &nabto_device_stream_core_callback, listenerContext);
    if (ec) {
        free(listenerContext);
        nabto_device_listener_free((NabtoDeviceListener*)listener);
        return NULL;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return (NabtoDeviceListener*)listener;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_listener_new_stream(NabtoDeviceListener* deviceListener, NabtoDeviceFuture** future, NabtoDeviceStream** stream)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_context* dev = listener->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (nabto_device_listener_get_type(listener) != NABTO_DEVICE_LISTENER_TYPE_STREAMS) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return NABTO_DEVICE_EC_INVALID_LISTENER;
    }
    np_error_code ec = nabto_device_listener_get_status(listener);
    if (ec != NABTO_EC_OK) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_error_core_to_api(ec);
    }
    struct nabto_device_stream_listener_context* listenerContext = (struct nabto_device_stream_listener_context*)nabto_device_listener_get_listener_data(listener);
    if (listenerContext->stream != NULL) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return NABTO_DEVICE_EC_OPERATION_IN_PROGRESS;
    }
    *stream = NULL;
    listenerContext->stream = stream;
    struct nabto_device_future* fut;
    // user reference must be set before as this call can resolve the future to the future queue
    ec = nabto_device_listener_create_future(listener, &fut);
    if (ec != NABTO_EC_OK) {
        // resetting user reference if future could not be created
        listenerContext->stream = NULL;
    } else {
        *future = (NabtoDeviceFuture*)fut;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

void NABTO_DEVICE_API nabto_device_stream_free(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_context* dev = str->dev;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    nc_stream_release(str->stream);
    free(str);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}


void nabto_device_stream_accept_callback(const np_error_code ec, void* userData)
{
    // this callback is from the core, the lock is already taken.
    struct nabto_device_stream* str = userData;
    nabto_api_future_queue_post(&str->dev->queueHead, str->acceptFut, nabto_device_error_core_to_api(ec));
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_accept(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    str->acceptFut = fut;
    np_error_code ec = nc_stream_async_accept(str->stream, nabto_device_stream_accept_callback, str);
    if (ec != NABTO_EC_OK) {
        nabto_api_future_queue_post(&str->dev->queueHead, fut, nabto_device_error_core_to_api(ec));
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}




NabtoDeviceConnectionRef NABTO_DEVICE_API nabto_device_stream_get_connection_ref(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceConnectionRef ref;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);

    ref = nc_device_get_connection_ref_from_stream(&str->dev->core, &str->stream->stream);

    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return ref;
}

void nabto_device_stream_read_callback(const np_error_code ec, void* userData)
{
    // this callback is from the core, the lock is already taken.
    struct nabto_device_stream* str = userData;

    nabto_api_future_queue_post(&str->dev->queueHead, str->readFut, nabto_device_error_core_to_api(ec));
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_read_all(NabtoDeviceStream* stream,
                                                void* buffer, size_t bufferLength,
                                                size_t* readLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    str->readFut = fut;
    np_error_code ec = nc_stream_async_read_all(str->stream, buffer, bufferLength, readLength, &nabto_device_stream_read_callback, str);
    if (ec) {
        nabto_api_future_queue_post(&str->dev->queueHead, fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_read_some(NabtoDeviceStream* stream,
                                                 void* buffer, size_t bufferLength,
                                                 size_t* readLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    str->readFut = fut;
    np_error_code ec = nc_stream_async_read_some(str->stream, buffer, bufferLength, readLength, &nabto_device_stream_read_callback, str);
    if (ec) {
        nabto_api_future_queue_post(&str->dev->queueHead, fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

void nabto_device_stream_write_callback(const np_error_code ec, void* userData)
{
    // this callback is from the core, the lock is already taken.
    struct nabto_device_stream* str = userData;

    nabto_api_future_queue_post(&str->dev->queueHead, str->writeFut, nabto_device_error_core_to_api(ec));
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_write(NabtoDeviceStream* stream,
                                             const void* buffer, size_t bufferLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    str->writeFut = fut;
    np_error_code ec = nc_stream_async_write(str->stream, buffer, bufferLength, &nabto_device_stream_write_callback, str);
    if (ec) {
        nabto_api_future_queue_post(&str->dev->queueHead, fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

void nabto_device_stream_close_callback(const np_error_code ec, void* userData)
{
    // this callback is from the core, the lock is already taken.
    struct nabto_device_stream* str = userData;

    NABTO_LOG_INFO(LOG, "stream async close core callback");
    nabto_api_future_queue_post(&str->dev->queueHead, str->closeFut, nabto_device_error_core_to_api(ec));
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_close(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    str->closeFut = fut;
    np_error_code ec = nc_stream_async_close(str->stream, &nabto_device_stream_close_callback, str);
    if (ec) {
        nabto_api_future_queue_post(&str->dev->queueHead, fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

/*******************************************
 * Streaming Api End
 *******************************************/

void nabto_device_stream_listener_callback(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData)
{
    struct nabto_device_stream_listener_context* listenerContext = (struct nabto_device_stream_listener_context*)listenerData;
    if (ec == NABTO_EC_OK) {
        struct nabto_device_stream* str = (struct nabto_device_stream*)eventData;
        if (listenerContext->stream != NULL) {
            nabto_api_future_set_error_code(future, NABTO_DEVICE_EC_OK);
            *listenerContext->stream = (NabtoDeviceStream*)str;
            listenerContext->stream = NULL;
        } else {
            NABTO_LOG_ERROR(LOG, "Tried to resolve new stream future, but stream reference was invalid");
            nabto_api_future_set_error_code(future, NABTO_DEVICE_EC_FAILED);
        }
        // using the stream structure as event structure means it will be freed when user calls stream_free
    } else if (ec == NABTO_EC_ABORTED) {
        nc_stream_manager_remove_listener(&listenerContext->coreListener);
        free(listenerContext);
    } else {
        // In error state streams on the listener queue will not reach the user, so they cant call stream_free
        struct nabto_device_stream* str = (struct nabto_device_stream*)eventData;
        nc_stream_release(str->stream);
        free(str);
    }
}


void nabto_device_stream_core_callback(np_error_code ec, struct nc_stream_context* stream, void* data)
{
    struct nabto_device_stream_listener_context* listenerContext = data;
    struct nabto_device_context* dev = listenerContext->device;
    NABTO_LOG_INFO(LOG, "stream_listener_callback");

    if (ec == NABTO_EC_OK) {
        struct nabto_device_stream* str = calloc(1, sizeof(struct nabto_device_stream));
        if (str == NULL) {
            nabto_device_listener_set_error_code(listenerContext->listener, NABTO_EC_OUT_OF_MEMORY);
            nc_stream_release(str->stream);
            return;
        }
        str->stream = stream;
        str->dev = dev;
        // using the stream structure directly as listener event, this means we dont free event untill user calls stream_free()
        np_error_code ec = nabto_device_listener_add_event(listenerContext->listener, str);
        if (ec != NABTO_EC_OK) {
            nc_stream_release(str->stream);
            free(str);
        }
        return;
    } else {
        nabto_device_listener_set_error_code(listenerContext->listener, ec);
    }
}
