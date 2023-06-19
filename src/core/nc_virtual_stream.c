#include "nc_virtual_stream.h"

#include <core/nc_connection.h>
#include <core/nc_stream_manager.h>

#include <platform/np_event_queue_wrapper.h>

static void nc_virtual_stream_event_callback(void* data)
{
    struct nc_stream_context* stream = (struct nc_stream_context*)data;
    if (stream->acceptCb) {
        nc_stream_callback cb = stream->acceptCb;
        stream->acceptCb = NULL;
        cb(NABTO_EC_OK, stream->acceptUserData);
    }
}

np_error_code nc_virtual_stream_init(struct np_platform* pl, struct nc_stream_context* ctx, struct nc_connection* conn, struct nc_stream_manager_context* streamManager, uint32_t port, nc_stream_callback cb, void* userdata)
{
    ctx->refCount = 0;
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

    np_error_code ec = np_event_queue_create_event(&pl->eq, &nc_virtual_stream_event_callback, ctx, &ctx->ev);

    if (ec != NABTO_EC_OK) {
        return ec;
    }

    nc_stream_manager_ready_for_accept(ctx->streamManager, ctx);
    return NABTO_EC_OK;
}

void nc_virtual_stream_client_stop(struct nc_stream_context* stream)
{

}


void nc_virtual_stream_server_accepted(struct nc_stream_context* stream)
{
    if (stream->virt.openedCb) {
        nc_stream_callback cb = stream->virt.openedCb;
        stream->virt.openedCb = NULL;
        cb(NABTO_EC_OK, stream->virt.openedData);
    }
}
