#include "nabto_device_stream.h"
#include "nabto_device_future.h"
#include <api/nabto_device_defines.h>
#include <platform/np_logging.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API


struct nabto_device_stream_listener_context {
    struct nabto_device_context* device;
    struct nabto_device_future* future;
    struct nc_stream_listener listener;
    NabtoDeviceStream** stream;
};

/*******************************************
 * Streaming Api
 *******************************************/

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_listen(NabtoDevice* device, uint32_t type, NabtoDeviceStream** stream)
{
    *stream = NULL;
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_future* fut = nabto_device_future_new(dev);
    if (!fut) {
        return NULL;
    }

    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_stream_listener_context* listenerContext = calloc(1, sizeof(struct nabto_device_stream_listener_context));
    // todo what if calloc fails
    listenerContext->device = dev;
    listenerContext->future = fut;
    listenerContext->stream = stream;
    np_error_code ec = nc_stream_manager_add_listener(&dev->core.streamManager, &listenerContext->listener, type, &nabto_device_stream_listener_callback, listenerContext);
    if (ec) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(ec));
        nabto_api_future_queue_post(&dev->queueHead, fut);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

void NABTO_DEVICE_API nabto_device_stream_free(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    str->readyToFree = true;

    // TODO
    //nabto_stream_release(str->stream);
    // TODO: resolve all futures
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
}


void nabto_device_stream_accept_callback(const np_error_code ec, void* userData)
{
    // this callback is from the core, the lock is already taken.
    struct nabto_device_stream* str = userData;
    nabto_api_future_set_error_code(str->acceptFut, nabto_device_error_core_to_api(ec));
    nabto_api_future_queue_post(&str->dev->queueHead, str->acceptFut);
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_accept(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    str->acceptFut = fut;
    np_error_code ec = nc_stream_async_accept(str->stream, nabto_device_stream_accept_callback, str);
    if (ec != NABTO_EC_OK) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(ec));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
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

    nabto_api_future_set_error_code(str->readFut, nabto_device_error_core_to_api(ec));
    nabto_api_future_queue_post(&str->dev->queueHead, str->readFut);
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
        nabto_api_future_set_error_code(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
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
        nabto_api_future_set_error_code(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

void nabto_device_stream_write_callback(const np_error_code ec, void* userData)
{
    // this callback is from the core, the lock is already taken.
    struct nabto_device_stream* str = userData;

    nabto_api_future_set_error_code(str->writeFut, nabto_device_error_core_to_api(ec));
    nabto_api_future_queue_post(&str->dev->queueHead, str->writeFut);
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
        nabto_api_future_set_error_code(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

void nabto_device_stream_close_callback(const np_error_code ec, void* userData)
{
    // this callback is from the core, the lock is already taken.
    struct nabto_device_stream* str = userData;

    nabto_api_future_set_error_code(str->closeFut, nabto_device_error_core_to_api(ec));
    nabto_api_future_queue_post(&str->dev->queueHead, str->closeFut);
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_close(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    str->closeFut = fut;
    np_error_code ec = nc_stream_async_close(str->stream, &nabto_device_stream_close_callback, str);
    if (ec) {
        nabto_api_future_set_error_code(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

/*******************************************
 * Streaming Api End
 *******************************************/


void nabto_device_stream_listener_callback(np_error_code ec, struct nc_stream_context* stream, void* data)
{
    struct nabto_device_stream_listener_context* listenerContext = data;
    struct nabto_device_context* dev = listenerContext->device;
    NABTO_LOG_INFO(LOG, "stream_listener_callback with str->listenFut: %u", listenerContext->future);

    if (ec == NABTO_EC_OK) {
        // TODO what if calloc fails
        struct nabto_device_stream* str = calloc(1, sizeof(struct nabto_device_stream));
        str->stream = stream;
        str->dev = dev;
        *(listenerContext->stream) = (NabtoDeviceStream*)str;
    }

    nabto_api_future_set_error_code(listenerContext->future, nabto_device_error_core_to_api(ec));
    nabto_api_future_queue_post(&dev->queueHead, listenerContext->future);

    free(listenerContext);
}
