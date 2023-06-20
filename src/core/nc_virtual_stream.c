#include "nc_virtual_stream.h"

#include <core/nc_connection.h>
#include <core/nc_stream_manager.h>

#include <platform/np_event_queue_wrapper.h>
#include <platform/np_logging.h>

#define LOG NABTO_LOG_MODULE_STREAM


static void nc_virtual_stream_event_callback(void* data)
{
    struct nc_stream_context* stream = (struct nc_stream_context*)data;
    if (stream->acceptCb) {
        nc_stream_callback cb = stream->acceptCb;
        stream->acceptCb = NULL;
        cb(NABTO_EC_OK, stream->acceptUserData);
    }
    nc_virtual_stream_server_accepted(stream);
}

np_error_code nc_virtual_stream_init(struct np_platform* pl, struct nc_stream_context* ctx, struct nc_connection* conn, struct nc_stream_manager_context* streamManager, uint32_t port, nc_stream_callback cb, void* userdata)
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
    ctx->virt.openedCb = cb;
    ctx->virt.openedData = userdata;
    ctx->virt.stopped = false;

    np_error_code ec = np_event_queue_create_event(&pl->eq, &nc_virtual_stream_event_callback, ctx, &ctx->ev);

    if (ec != NABTO_EC_OK) {
        return ec;
    }

    nc_stream_manager_ready_for_accept(ctx->streamManager, ctx);
    return NABTO_EC_OK;
}

void nc_virtual_stream_client_stop(struct nc_stream_context* stream)
{
    if (stream->virt.stopped) {
        return;
    }

    stream->virt.stopped = true;

    nc_stream_callback openedCb = stream->virt.openedCb;
    stream->virt.openedCb = NULL;

    nc_stream_callback readAllCb = stream->virt.readAllCb;
    stream->virt.readAllCb = NULL;

    nc_stream_callback readSomeCb = stream->virt.readSomeCb;
    stream->virt.readSomeCb = NULL;

    nc_stream_callback writeCb = stream->virt.writeCb;
    stream->virt.writeCb = NULL;

    nc_stream_callback closeCb = stream->virt.closeCb;
    stream->virt.closeCb = NULL;

    if (openedCb) {
        openedCb(NABTO_EC_ABORTED, stream->virt.openedData);
    }
    if (readAllCb) {
        readAllCb(NABTO_EC_ABORTED, stream->virt.readUserData);
    }
    if (readSomeCb) {
        readSomeCb(NABTO_EC_ABORTED, stream->virt.readUserData);
    }
    if (writeCb) {
        writeCb(NABTO_EC_ABORTED, stream->virt.writeUserData);
    }
    if (closeCb) {
        closeCb(NABTO_EC_ABORTED, stream->virt.closeUserData);
    }

    nc_stream_resolve_read(stream, NABTO_EC_ABORTED);
}


void nc_virtual_stream_server_accepted(struct nc_stream_context* stream)
{
    if (stream->virt.openedCb) {
        nc_stream_callback cb = stream->virt.openedCb;
        stream->virt.openedCb = NULL;
        cb(NABTO_EC_OK, stream->virt.openedData);
    }
}


void nc_virtual_stream_destroy(struct nc_stream_context* stream)
{
    nc_stream_ref_count_dec(stream);
}



void nc_virtual_stream_server_read(struct nc_stream_context* stream)
{

}
