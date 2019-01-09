#include "nabto_device_stream.h"
#include <api/nabto_device_defines.h>
#include <platform/np_logging.h>
#define LOG NABTO_LOG_MODULE_API


void nabto_device_stream_resolve_read(struct nabto_device_stream* str, np_error_code ec)
{
    str->readLength = NULL;
    str->readBuffer = NULL;
    str->readBufferLength = 0;
    
    if (str->readAllFut) {
        nabto_api_future_set_error_code(str->readAllFut, ec);
        nabto_api_future_queue_post(&str->dev->queueHead, str->readAllFut);
        str->readAllFut = NULL;
    } else if (str->readSomeFut) {
        nabto_api_future_set_error_code(str->readSomeFut, ec);
        nabto_api_future_queue_post(&str->dev->queueHead, str->readSomeFut);
        str->readSomeFut = NULL;
    } else {
        NABTO_LOG_ERROR(LOG, "Tried to resolve read futures which does not exist");
    }
}

void nabto_device_stream_listener_callback(struct nabto_stream* stream, void* data)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)data;
    NABTO_LOG_INFO(LOG, "stream_listener_callback with str->listenFut: %u", str->listenFut);
    str->stream = stream;
    if (str->listenFut) {
        nabto_api_future_set_error_code(str->listenFut, NABTO_EC_OK);
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
            nabto_api_future_set_error_code(str->writeFut, NABTO_EC_OK);
            nabto_api_future_queue_post(&str->dev->queueHead, str->writeFut);
            str->writeFut = NULL;
        } else {
            str->writeBuffer += written;
            str->writeBufferLength -= written;
            nabto_device_stream_do_write_all(str);
        }
    } else {
        nabto_api_future_set_error_code(str->writeFut, nc_stream_status_to_ec(status));
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
        nabto_api_future_set_error_code(str->closeFut, NABTO_EC_OK);
        nabto_api_future_queue_post(&str->dev->queueHead, str->closeFut);
        str->closeFut = NULL;
    } else {
        nabto_api_future_set_error_code(str->closeFut, nc_stream_status_to_ec(status));
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
                nabto_api_future_set_error_code(str->acceptFut, NABTO_EC_OK);
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
                nabto_api_future_set_error_code(str->closeFut, NABTO_EC_OK);
                nabto_api_future_queue_post(&str->dev->queueHead, str->closeFut);
                str->closeFut = NULL;
            }
            break;
        case NABTO_STREAM_APPLICATION_EVENT_TYPE_CLOSED:
            if (str->writeFut) {
                nabto_device_stream_do_write_all(str);
            }
            if (str->acceptFut) {
                nabto_api_future_set_error_code(str->acceptFut, NABTO_EC_ABORTED);
                nabto_api_future_queue_post(&str->dev->queueHead, str->acceptFut);
                str->acceptFut = NULL;
            }
            nabto_device_stream_do_read(str);
            nabto_device_stream_handle_close(str);
            break;
        default:
            NABTO_LOG_ERROR(LOG, "Unknown stream application event type %s", nabto_stream_application_event_type_to_string(eventType));
    }
}
