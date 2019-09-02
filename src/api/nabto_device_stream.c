#include "nabto_device_stream.h"
#include "nabto_device_future.h"
#include <api/nabto_device_defines.h>
#include <platform/np_logging.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API


/*******************************************
 * Streaming Api
 *******************************************/

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_listen(NabtoDevice* device, NabtoDeviceStream** stream)
{
    *stream = NULL;
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_future* fut = nabto_device_future_new(dev);
    if (!fut) {
        return NULL;
    }
    if (dev->streamListenFuture) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&dev->queueHead, fut);
    } else {
        dev->streamListenFuture = fut;
        dev->streamListenStream = (struct nabto_device_stream**)stream;
        nc_stream_manager_set_listener(&dev->core.streamManager, &nabto_device_stream_listener_callback, dev);
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
    struct nabto_device_stream* str = userData;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);

    nabto_api_future_set_error_code(str->acceptFut, nabto_device_error_core_to_api(ec));
    nabto_api_future_queue_post(&str->dev->queueHead, str->acceptFut);
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_accept(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);
    nabto_device_threads_mutex_lock(str->dev->eventMutex);

    np_error_code ec = nc_stream_async_accept(str->stream, nabto_device_stream_accept_callback, str);
    if (ec != NABTO_EC_OK) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(ec));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
    } else {
        str->acceptFut = fut;
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
    struct nabto_device_stream* str = userData;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);

    nabto_api_future_set_error_code(str->readFut, nabto_device_error_core_to_api(ec));
    nabto_api_future_queue_post(&str->dev->queueHead, str->readFut);
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_read_all(NabtoDeviceStream* stream,
                                                void* buffer, size_t bufferLength,
                                                size_t* readLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    np_error_code ec = nc_stream_async_read_all(str->stream, buffer, bufferLength, readLength, &nabto_device_stream_read_callback, str);
    if (ec) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
    } else {
        str->readFut = fut;
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
    np_error_code ec = nc_stream_async_read_some(str->stream, buffer, bufferLength, readLength, &nabto_device_stream_read_callback, str);
    if (ec) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
    } else {
        str->readFut = fut;
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

void nabto_device_stream_write_callback(const np_error_code ec, void* userData)
{
    struct nabto_device_stream* str = userData;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);

    nabto_api_future_set_error_code(str->writeFut, nabto_device_error_core_to_api(ec));
    nabto_api_future_queue_post(&str->dev->queueHead, str->writeFut);
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_write(NabtoDeviceStream* stream,
                                             const void* buffer, size_t bufferLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    np_error_code ec = nc_stream_async_write(str->stream, buffer, bufferLength, &nabto_device_stream_write_callback, str);
    if (ec) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
    } else {
        str->writeFut = fut;
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

void nabto_device_stream_close_callback(const np_error_code ec, void* userData)
{
    struct nabto_device_stream* str = userData;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);

    nabto_api_future_set_error_code(str->closeFut, nabto_device_error_core_to_api(ec));
    nabto_api_future_queue_post(&str->dev->queueHead, str->closeFut);
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_close(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);

    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    np_error_code ec = nc_stream_async_close(str->stream, &nabto_device_stream_close_callback, str);
    if (ec) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
    } else {
        str->closeFut = fut;
    }
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

/*******************************************
 * Streaming Api End
 *******************************************/


void nabto_device_stream_listener_callback(np_error_code ec, struct nc_stream_context* stream, void* data)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)data;
    NABTO_LOG_INFO(LOG, "stream_listener_callback with str->listenFut: %u", dev->streamListenFuture);

    if (dev->streamListenFuture) {

        if (ec == NABTO_DEVICE_EC_OK) {
            struct nabto_device_stream* str = calloc(1, sizeof(struct nabto_device_stream));
            str->stream = stream;
            str->dev = dev;
            *(dev->streamListenStream) = str;
        }

        nabto_api_future_set_error_code(dev->streamListenFuture, nabto_device_error_core_to_api(ec));
        nabto_api_future_queue_post(&dev->queueHead, dev->streamListenFuture);

        dev->streamListenFuture = NULL;
    } else {
        NABTO_LOG_INFO(LOG, "stream_listener had no listen future");
    }
}
