#include "nc_virtual_stream.h"

#include <core/nc_connection.h>
#include <core/nc_stream_manager.h>

#include <platform/np_event_queue_wrapper.h>
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_STREAM


np_error_code nc_virtual_stream_init(struct np_platform* pl, struct nc_stream_context* ctx, struct nc_connection* conn, struct nc_stream_manager_context* streamManager, uint32_t port, struct np_completion_event* openedEv)
{
    // Start refCount at 1 to ensure stream is not freed until user freed the virtual stream
    ctx->refCount = 1;
    ctx->stopped = false;
    ctx->conn = conn;
    ctx->streamManager = streamManager;
    ctx->pl = pl;
    ctx->isSending = false;
    ctx->connectionRef = conn->connectionRef;
    ctx->accepted = false;
    ctx->isVirtual = true;
    ctx->virt.port = port;
    ctx->virt.openedEv = openedEv;
    ctx->virt.stopped = false;

    nc_stream_manager_ready_for_accept(ctx->streamManager, ctx);
    return NABTO_EC_OK;
}

void nc_virtual_stream_client_stop(struct nc_stream_context* stream)
{
    NABTO_LOG_TRACE(LOG, "nc_virtual_stream_client_stop");
    if (stream->virt.stopped) {
        return;
    }

    stream->virt.stopped = true;

    if (stream->virt.openedEv) {
        np_completion_event_resolve(stream->virt.openedEv, NABTO_EC_ABORTED);
        stream->virt.openedEv = NULL;
    }

    if (stream->virt.readAllEv) {
        np_completion_event_resolve(stream->virt.readAllEv, NABTO_EC_ABORTED);
        stream->virt.readAllEv = NULL;
    }

    if (stream->virt.readSomeEv) {
        np_completion_event_resolve(stream->virt.readSomeEv, NABTO_EC_ABORTED);
        stream->virt.readSomeEv = NULL;
    }

    if (stream->virt.writeEv) {
        np_completion_event_resolve(stream->virt.writeEv, NABTO_EC_ABORTED);
        stream->virt.writeEv = NULL;
    }

    if (stream->virt.closeEv) {
        np_completion_event_resolve(stream->virt.closeEv, NABTO_EC_ABORTED);
        stream->virt.closeEv = NULL;
    }

    if (stream->readAllEv || stream->readSomeEv) {
        nc_stream_resolve_read(stream, NABTO_EC_ABORTED);
    }
    if (stream->writeEv) {
        np_completion_event_resolve(stream->writeEv, NABTO_EC_ABORTED);
        stream->writeEv = NULL;
    }
}


void nc_virtual_stream_server_accepted(struct nc_stream_context* stream)
{
    NABTO_LOG_TRACE(LOG, "nc_virtual_stream_server_accepted");
    if (stream->virt.openedEv) {
        np_completion_event_resolve(stream->virt.openedEv, NABTO_EC_OK);
        stream->virt.openedEv = NULL;
    }
    if (stream->acceptEv) {
        np_completion_event_resolve(stream->acceptEv, NABTO_EC_OK);
        stream->acceptEv = NULL;
    }
}


void nc_virtual_stream_destroy(struct nc_stream_context* stream)
{
    NABTO_LOG_TRACE(LOG, "nc_virtual_stream_destroy");
    nc_stream_ref_count_dec(stream);
}


void nc_virtual_stream_do_write(struct nc_stream_context* stream)
{
    if (stream->readAllEv != NULL || stream->readSomeEv != NULL) {
        // Server read is ready, copy data
        size_t written = stream->virt.writeBufferLength > stream->readBufferLength ? stream->readBufferLength : stream->virt.writeBufferLength;
        memcpy(stream->readBuffer, stream->virt.writeBuffer, written);
        *stream->readLength += written;
        NABTO_LOG_TRACE(LOG, "Virtually written %u Bytes to read buffer", written);

        if (stream->virt.writeBufferLength > stream->readBufferLength) {
            // store writeEv and resolve read
            stream->virt.writeBuffer = ((uint8_t*)stream->virt.writeBuffer) + written;
            stream->virt.writeBufferLength -= written;
            nc_stream_resolve_read(stream, NABTO_EC_OK);
            NABTO_LOG_TRACE(LOG, "Virtually written more than read buffer. Resolving read");
        }
        else if (stream->virt.writeBufferLength < stream->readBufferLength &&
            stream->readAllEv != NULL) {
            // update readBuffer and resolve write

            stream->readBuffer = ((uint8_t*)stream->readBuffer) + written;
            stream->readBufferLength -= written;
            np_completion_event_resolve(stream->virt.writeEv, NABTO_EC_OK);
            stream->virt.writeBuffer = NULL;
            stream->virt.writeBufferLength = 0;
            stream->virt.writeEv = NULL;
            NABTO_LOG_TRACE(LOG, "Virtually written less than read All buffer. Resolving write");
        }
        else {
            // bufferLength == readBufferLength ||
            // bufferLength < readBufferLength && readSomeEv != NULL
            // resolve both
            np_completion_event_resolve(stream->virt.writeEv, NABTO_EC_OK);
            stream->virt.writeBuffer = NULL;
            stream->virt.writeBufferLength = 0;
            stream->virt.writeEv = NULL;
            nc_stream_resolve_read(stream, NABTO_EC_OK);
            NABTO_LOG_TRACE(LOG, "Virtually written less than or equal to read buffer. Resolving read and write");
        }
    }
}


void nc_virtual_stream_server_read(struct nc_stream_context* stream)
{
    if (stream->virt.writeEv != NULL){
        nc_virtual_stream_do_write(stream);
    }
}

void nc_virtual_stream_client_async_write(struct nc_stream_context* stream, const void* buffer, size_t bufferLength, struct np_completion_event* writeEv)
{
    NABTO_LOG_TRACE(LOG, "nc_virtual_stream_client_async_write");
    if (stream->virt.writeEv != NULL) {
        return np_completion_event_resolve(writeEv, NABTO_EC_OPERATION_IN_PROGRESS);
    }
    stream->virt.writeEv = writeEv;
    stream->virt.writeBuffer = buffer;
    stream->virt.writeBufferLength = bufferLength;
    nc_virtual_stream_do_write(stream);
}

void nc_virtual_stream_resolve_read(struct nc_stream_context* stream, np_error_code ec)
{
    stream->virt.readLength = NULL;
    stream->virt.readBuffer = NULL;
    stream->virt.readBufferLength = 0;

    if (stream->virt.readAllEv) {
        np_completion_event_resolve(stream->virt.readAllEv, ec);
        stream->virt.readAllEv = NULL;
    } else if (stream->virt.readSomeEv) {
        np_completion_event_resolve(stream->virt.readSomeEv, ec);
        stream->virt.readSomeEv = NULL;
    } else {
        NABTO_LOG_ERROR(LOG, "Tried to resolve virtual read events which does not exist");
    }
}

void nc_virtual_stream_do_read(struct nc_stream_context* stream)
{
    if (stream->writeEv != NULL) {
        // Server write is ready, copy data
        size_t readen = stream->virt.readBufferLength > stream->writeBufferLength ? stream->writeBufferLength : stream->virt.readBufferLength;
        memcpy(stream->virt.readBuffer, stream->writeBuffer, readen);
        *stream->virt.readLength += readen;

        if (stream->writeBufferLength > stream->virt.readBufferLength) {
            // resolve read
            stream->writeBuffer = ((uint8_t*)stream->writeBuffer) + readen;
            stream->writeBufferLength -= readen;
            nc_virtual_stream_resolve_read(stream, NABTO_EC_OK);
        }
        else if (stream->writeBufferLength < stream->virt.readBufferLength &&
            stream->virt.readAllEv != NULL) {
            // update readBuffer and resolve write

            stream->virt.readBuffer = ((uint8_t*)stream->virt.readBuffer) + readen;
            stream->virt.readBufferLength -= readen;
            np_completion_event_resolve(stream->writeEv, NABTO_EC_OK);
            stream->writeEv = NULL;
        }
        else {
            // bufferLength == readBufferLength ||
            // bufferLength < readBufferLength && readSomeEv != NULL
            // resolve both
            np_completion_event_resolve(stream->writeEv, NABTO_EC_OK);
            stream->writeEv = NULL;
            nc_virtual_stream_resolve_read(stream, NABTO_EC_OK);
        }
    }
}

void nc_virtual_stream_server_write(struct nc_stream_context* stream)
{
    if (stream->virt.readAllEv != NULL || stream->virt.readSomeEv != NULL){
        nc_virtual_stream_do_read(stream);
    }
}

void nc_virtual_stream_client_async_read_all(struct nc_stream_context* stream, void* buffer, size_t bufferLength, size_t* readLength, struct np_completion_event* readEv)
{
    NABTO_LOG_TRACE(LOG, "nc_virtual_stream_client_async_read_all");
    if (stream->virt.readAllEv != NULL || stream->virt.readSomeEv != NULL) {
        return np_completion_event_resolve(readEv, NABTO_EC_OPERATION_IN_PROGRESS);
    }
    stream->virt.readAllEv = readEv;
    stream->virt.readBuffer = buffer;
    stream->virt.readBufferLength = bufferLength;
    stream->virt.readLength = readLength;
    *stream->virt.readLength = 0;
    nc_virtual_stream_do_read(stream);

}

void nc_virtual_stream_client_async_read_some(struct nc_stream_context* stream, void* buffer, size_t bufferLength, size_t* readLength, struct np_completion_event* readEv)
{
    NABTO_LOG_TRACE(LOG, "nc_virtual_stream_client_async_read_some");
    if (stream->virt.readAllEv != NULL || stream->virt.readSomeEv != NULL) {
        return np_completion_event_resolve(readEv, NABTO_EC_OPERATION_IN_PROGRESS);
    }
    stream->virt.readSomeEv = readEv;
    stream->virt.readBuffer = buffer;
    stream->virt.readBufferLength = bufferLength;
    stream->virt.readLength = readLength;
    *stream->virt.readLength = 0;
    nc_virtual_stream_do_read(stream);

}
