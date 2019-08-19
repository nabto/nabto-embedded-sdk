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
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_stream* str = (struct nabto_device_stream*)malloc(sizeof(struct nabto_device_stream));
    struct nabto_device_future* fut = nabto_device_future_new(dev);
    memset(str, 0, sizeof(struct nabto_device_stream));
    *stream = (NabtoDeviceStream*)str;
    str->listenFut = fut;
    str->dev = dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    nc_stream_manager_set_listener(&dev->core.streamManager, &nabto_device_stream_listener_callback, str);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

void NABTO_DEVICE_API nabto_device_stream_free(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    str->readyToFree = true;
    nabto_stream_release(str->stream);
    // TODO: resolve all futures
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
}



NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_accept(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);
    if (str->acceptFut) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return (NabtoDeviceFuture*)fut;
    }
    str->acceptFut = fut;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    nabto_stream_set_application_event_callback(str->stream, &nabto_device_stream_application_event_callback, str);
    nabto_stream_accept(str->stream);
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

NabtoDeviceConnectionRef NABTO_DEVICE_API nabto_device_stream_get_connection_ref(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceConnectionRef ref;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);

    ref = nc_device_get_connection_ref_from_stream(&str->dev->core, str->stream);

    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return ref;
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_read_all(NabtoDeviceStream* stream,
                                                void* buffer, size_t bufferLength,
                                                size_t* readLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);
    if (str->readSomeFut || str->readAllFut) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return (NabtoDeviceFuture*)fut;
    }
    str->readAllFut = fut;
    str->readBuffer = buffer;
    str->readBufferLength = bufferLength;
    str->readLength = readLength;
    *str->readLength = 0;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    nabto_device_stream_do_read(str);
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_read_some(NabtoDeviceStream* stream,
                                                 void* buffer, size_t bufferLength,
                                                 size_t* readLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);
    if (str->readSomeFut || str->readAllFut) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return (NabtoDeviceFuture*)fut;
    }
    str->readSomeFut = fut;
    str->readBuffer = buffer;
    str->readBufferLength = bufferLength;
    str->readLength = readLength;
    *str->readLength = 0;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    nabto_device_stream_do_read(str);
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_write(NabtoDeviceStream* stream,
                                             const void* buffer, size_t bufferLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);
    if (str->writeFut) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return (NabtoDeviceFuture*)fut;
    }
    str->writeFut = fut;
    str->writeBuffer = buffer;
    str->writeBufferLength = bufferLength;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    nabto_device_stream_do_write_all(str);
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_close(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    struct nabto_device_future* fut = nabto_device_future_new(str->dev);
    if (str->closeFut) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return (NabtoDeviceFuture*)fut;
    }
    str->closeFut = fut;
    nabto_device_stream_handle_close(str);
    return (NabtoDeviceFuture*)fut;
}

/*******************************************
 * Streaming Api End
 *******************************************/


void nabto_device_stream_resolve_read(struct nabto_device_stream* str, np_error_code ec)
{
    str->readLength = NULL;
    str->readBuffer = NULL;
    str->readBufferLength = 0;

    if (str->readAllFut) {
        nabto_api_future_set_error_code(str->readAllFut, nabto_device_error_core_to_api(ec));
        nabto_api_future_queue_post(&str->dev->queueHead, str->readAllFut);
        str->readAllFut = NULL;
    } else if (str->readSomeFut) {
        nabto_api_future_set_error_code(str->readSomeFut, nabto_device_error_core_to_api(ec));
        nabto_api_future_queue_post(&str->dev->queueHead, str->readSomeFut);
        str->readSomeFut = NULL;
    } else {
        NABTO_LOG_ERROR(LOG, "Tried to resolve read futures which does not exist");
    }
}

void nabto_device_stream_listener_callback(np_error_code ec, struct nabto_stream* stream, void* data)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)data;
    NABTO_LOG_INFO(LOG, "stream_listener_callback with str->listenFut: %u", str->listenFut);
    str->stream = stream;
    if (str->listenFut) {
        nabto_api_future_set_error_code(str->listenFut, nabto_device_error_core_to_api(ec));
        nabto_api_future_queue_post(&str->dev->queueHead, str->listenFut);
        str->listenFut = NULL;
    } else {
        NABTO_LOG_INFO(LOG, "stream_listener had no listen future");
    }
}
void nabto_device_stream_do_read(struct nabto_device_stream* str)
{
    if (!str->readAllFut && !str->readSomeFut) {
        // data available but no one wants it
        NABTO_LOG_INFO(LOG, "Stream do read with no read future");
    } else {
        size_t readen;
        nabto_stream_status status = nabto_stream_read_buffer(str->stream, str->readBuffer, str->readBufferLength, &readen);
        if (status == NABTO_STREAM_STATUS_OK) {
            if (readen == 0) {
                // wait for a new event saying more data is ready.
            } else {
                *str->readLength += readen;
                str->readBuffer += readen;
                str->readBufferLength -= readen;
                if (str->readAllFut) {
                    if (str->readBufferLength == 0) {
                        nabto_device_stream_resolve_read(str, NABTO_EC_OK);
                    } else {
                        // read more until 0 or error
                        nabto_device_stream_do_read(str);
                    }
                } else if (str->readSomeFut) {
                    nabto_device_stream_resolve_read(str, NABTO_EC_OK);
                } else {
                    // Still no future? we just checked this!
                    NABTO_LOG_ERROR(LOG, "Reached imposible stream state. Futures exist but dont");
                }
            }
        } else {
            nabto_device_stream_resolve_read(str, nc_stream_status_to_ec(status));
        }
    }
}

void nabto_device_stream_do_write_all(struct nabto_device_stream* str)
{
    size_t written;
    nabto_stream_status status = nabto_stream_write_buffer(str->stream, str->writeBuffer, str->writeBufferLength, &written);
    if (status == NABTO_STREAM_STATUS_OK) {
        if (written == 0) {
            // would block
            return;
        } else if (written == str->writeBufferLength) {
            nabto_api_future_set_error_code(str->writeFut, NABTO_DEVICE_EC_OK);
            nabto_api_future_queue_post(&str->dev->queueHead, str->writeFut);
            str->writeFut = NULL;
        } else {
            str->writeBuffer += written;
            str->writeBufferLength -= written;
            nabto_device_stream_do_write_all(str);
        }
    } else {
        nabto_api_future_set_error_code(str->writeFut, nabto_device_error_core_to_api(nc_stream_status_to_ec(status)));
        nabto_api_future_queue_post(&str->dev->queueHead, str->writeFut);
        str->writeFut = NULL;
    }

}

void nabto_device_stream_handle_close(struct nabto_device_stream* str)
{
    if (!str->closeFut) {
        return;
    }
    nabto_stream_status status = nabto_stream_close(str->stream);
    if (status == NABTO_STREAM_STATUS_OK) {
        return;
    } else if (status == NABTO_STREAM_STATUS_CLOSED) {
        nabto_api_future_set_error_code(str->closeFut, NABTO_DEVICE_EC_OK);
        nabto_api_future_queue_post(&str->dev->queueHead, str->closeFut);
        str->closeFut = NULL;
    } else {
        nabto_api_future_set_error_code(str->closeFut, nabto_device_error_core_to_api(nc_stream_status_to_ec(status)));
        nabto_api_future_queue_post(&str->dev->queueHead, str->closeFut);
        str->closeFut = NULL;
    }
}

void nabto_device_stream_application_event_callback(nabto_stream_application_event_type eventType, void* data)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)data;
    switch(eventType) {
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_OPENED:
            if (str->acceptFut) {
                nabto_api_future_set_error_code(str->acceptFut, NABTO_DEVICE_EC_OK);
                NABTO_LOG_TRACE(LOG, "stream opened");
                nabto_api_future_queue_post(&str->dev->queueHead, str->acceptFut);
                str->acceptFut = NULL;
            }
            break;
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_DATA_READY:
            nabto_device_stream_do_read(str);
            break;
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_DATA_WRITE:
            if (str->writeFut) {
                nabto_device_stream_do_write_all(str);
            }
            break;
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_READ_CLOSED:
            nabto_device_stream_do_read(str);
            break;
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_WRITE_CLOSED:
            if (str->closeFut) {
                nabto_api_future_set_error_code(str->closeFut, NABTO_DEVICE_EC_OK);
                nabto_api_future_queue_post(&str->dev->queueHead, str->closeFut);
                str->closeFut = NULL;
            }
            break;
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_CLOSED:
            if (str->writeFut) {
                nabto_device_stream_do_write_all(str);
            }
            if (str->acceptFut) {
                nabto_api_future_set_error_code(str->acceptFut, nabto_device_error_core_to_api(NABTO_EC_ABORTED));
                nabto_api_future_queue_post(&str->dev->queueHead, str->acceptFut);
                str->acceptFut = NULL;
            }
            nabto_device_stream_do_read(str);
            nabto_device_stream_handle_close(str);


            if (str->readyToFree) {
                free(str);
            } else {
                NABTO_LOG_ERROR(LOG, "ended in closed state but the stream has not been freed by the user yet");
            }
            break;
        default:
            NABTO_LOG_ERROR(LOG, "Unknown stream application event type %s", nabto_stream_application_event_type_to_string(eventType));
    }
}
