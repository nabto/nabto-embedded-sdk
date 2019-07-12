#include "nc_keep_alive.h"
#include <platform/np_event_queue.h>
#include <platform/np_logging.h>
#include <core/nc_packet.h>

#include <string.h>

#define LOG NABTO_LOG_MODULE_KEEP_ALIVE


enum nc_keep_alive_action{
    DO_NOTHING,
    SEND_KA,
    KA_TIMEOUT,
    DTLS_ERROR
};

void nc_keep_alive_wait(struct nc_keep_alive_context* ctx);
enum nc_keep_alive_action nc_keep_alive_should_send(struct nc_keep_alive_context* ctx);
void nc_keep_alive_event(const np_error_code ec, void* data);
void nc_keep_alive_send_req(struct nc_keep_alive_context* ctx);
void nc_keep_alive_close(struct nc_keep_alive_context* ctx, const np_error_code ec);
void nc_keep_alive_send_cb(const np_error_code ec, void* data);
void nc_keep_alive_recv(const np_error_code ec, uint8_t channelId, uint64_t seq,
                        np_communication_buffer* buf, uint16_t bufferSize, void* data);

// MTU FUNCTIONS
void nc_keep_alive_send_mtu_req(struct nc_keep_alive_context* ctx, uint16_t size);
void nc_keep_alive_mtu_discover_retry(const np_error_code ec, void* data);
void nc_keep_alive_mtu_resolve_discovery(struct nc_keep_alive_context* ctx, np_error_code ec, uint16_t mtu);
void nc_keep_alive_mtu_handle_response(struct nc_keep_alive_context* ctx, uint32_t seq);

void nc_keep_alive_init_cli(struct np_platform* pl, struct nc_keep_alive_context* ctx, np_dtls_cli_context* conn, keep_alive_callback cb, void* data)
{
    memset(ctx, 0, sizeof(struct nc_keep_alive_context));
    ctx->pl = pl;
    ctx->buf = ctx->pl->buf.allocate();
    ctx->isCli = true;
    ctx->cli = conn;
    ctx->cb = cb;
    ctx->data = data;
    ctx->sending = false;
    ctx->mtuSeq = 1;
}

void nc_keep_alive_init_srv(struct np_platform* pl, struct nc_keep_alive_context* ctx, struct np_dtls_srv_connection* conn, keep_alive_callback cb, void* data)
{
    memset(ctx, 0, sizeof(struct nc_keep_alive_context));
    ctx->pl = pl;
    ctx->buf = ctx->pl->buf.allocate();
    ctx->isCli = false;
    ctx->srv = conn;
    ctx->cb = cb;
    ctx->data = data;
    ctx->sending = false;
    ctx->mtuSeq = 1;
}

np_error_code nc_keep_alive_start(struct np_platform* pl, struct nc_keep_alive_context* ctx, uint32_t interval, uint8_t retryInterval, uint8_t maxRetries)
{
    NABTO_LOG_TRACE(LOG, "starting keep alive with interval: %u, retryInt: %u, maxRetries: %u", interval, retryInterval, maxRetries);
    if (pl != ctx->pl) {
        // either uninitialized or changed platform
        return NABTO_EC_FAILED;
    }
    ctx->kaInterval = interval;
    ctx->kaRetryInterval = retryInterval;
    ctx->kaMaxRetries = maxRetries;
    ctx->n = ctx->kaInterval/ctx->kaRetryInterval/1000;
/*    if (ctx->isCli) {
        ctx->pl->dtlsC.async_recv_from(ctx->pl, ctx->cli, AT_KEEP_ALIVE, &nc_keep_alive_recv, ctx);
    } else {
        ctx->pl->dtlsS.async_recv_from(ctx->pl, ctx->srv, AT_KEEP_ALIVE, &nc_keep_alive_recv, ctx);
        }*/
    nc_keep_alive_wait(ctx);
    return NABTO_EC_OK;
}

void nc_keep_alive_wait(struct nc_keep_alive_context* ctx)
{
    np_event_queue_post_timed_event(ctx->pl, &ctx->kaEv, ctx->kaRetryInterval*1000, &nc_keep_alive_event, ctx);
}

void nc_keep_alive_event(const np_error_code ec, void* data)
{
    struct nc_keep_alive_context* ctx = (struct nc_keep_alive_context*)data;
    if (ec != NABTO_EC_OK) {
        nc_keep_alive_close(ctx, ec);
    } else {
        enum nc_keep_alive_action action = nc_keep_alive_should_send(ctx);
        switch(action) {
            case DO_NOTHING:
                nc_keep_alive_wait(ctx);
                break;
            case SEND_KA:
                nc_keep_alive_send_req(ctx);
                nc_keep_alive_wait(ctx);
                break;
            case KA_TIMEOUT:
                nc_keep_alive_close(ctx, NABTO_EC_KEEP_ALIVE_TIMEOUT);
                break;
            case DTLS_ERROR:
                return;
        }
    }
}

enum nc_keep_alive_action nc_keep_alive_should_send(struct nc_keep_alive_context* ctx)
{
    uint32_t recvCount;
    uint32_t sentCount;
    np_error_code ec;
    if(ctx->isCli) {
        ec = ctx->pl->dtlsC.get_packet_count(ctx->cli, &recvCount, &sentCount);
    } else {
        ec = ctx->pl->dtlsS.get_packet_count(ctx->srv, &recvCount, &sentCount);
    }
//    NABTO_LOG_TRACE(LOG, "lastRecvCount: %u, recvCount: %u, LastSentCount: %u, sentCount: %u", ctx->lastRecvCount, recvCount, ctx->lastSentCount, sentCount);
    if (ec != NABTO_EC_OK) {
        nc_keep_alive_close(ctx, ec);
        return DTLS_ERROR;
    }
    if (ctx->lostKeepAlives > ctx->kaMaxRetries+ctx->n) {
        return KA_TIMEOUT;
    }
    if (recvCount > ctx->lastRecvCount && sentCount > ctx->lastSentCount) {
        ctx->lostKeepAlives = 0;
        ctx->lastRecvCount = recvCount;
        ctx->lastSentCount = sentCount;
        return DO_NOTHING;
    } else {
        ctx->lostKeepAlives++;
        if(ctx->lostKeepAlives > ctx->n) {
            return SEND_KA;
        } else {
            return DO_NOTHING;
        }
    }
}

void nc_keep_alive_send_req(struct nc_keep_alive_context* ctx)
{
    uint8_t* start = ctx->pl->buf.start(ctx->buf);
    if (ctx->sending) {
        NABTO_LOG_TRACE(LOG, "Already sending KA packet, ignoring send request");
        return;
    }
    ctx->sending = true;
    start[0] = (enum application_data_type)AT_KEEP_ALIVE;
    start[1] = (enum keep_alive_content_type)CT_KEEP_ALIVE_REQUEST;
    memset((start+2), 0, 16);
    NABTO_LOG_TRACE(LOG, "Sending keep alive request: ");
    NABTO_LOG_BUF(LOG, start, 16+NABTO_PACKET_HEADER_SIZE);
    if(ctx->isCli) {
        ctx->pl->dtlsC.async_send_to(ctx->pl, ctx->cli, 0xff, start, 16+NABTO_PACKET_HEADER_SIZE, &nc_keep_alive_send_cb, ctx);
    } else {
        ctx->sendCtx.buffer = start;
        ctx->sendCtx.bufferSize = 16+NABTO_PACKET_HEADER_SIZE;
        ctx->sendCtx.cb = &nc_keep_alive_send_cb;
        ctx->sendCtx.data = ctx;
        ctx->pl->dtlsS.async_send_data(ctx->pl, ctx->srv, &ctx->sendCtx);
    }
}

void nc_keep_alive_send_cb(const np_error_code ec, void* data)
{
    struct nc_keep_alive_context* ctx = (struct nc_keep_alive_context*)data;
    NABTO_LOG_INFO(LOG, "keep alive send cb");
    ctx->sending = false;
    if(ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Keep alive received error state from DTLS: %s", np_error_code_to_string(ec));
        nc_keep_alive_close(ctx, ec);
        return;
    }
}

void nc_keep_alive_close(struct nc_keep_alive_context* ctx, const np_error_code ec)
{
    NABTO_LOG_WARN(LOG, "Keep alive closing with error code: %u", ec);
    np_event_queue_cancel_timed_event(ctx->pl, &ctx->kaEv);
    if (ctx->mtuCb) {
        nc_keep_alive_mtu_resolve_discovery(ctx, ec, NC_KEEP_ALIVE_MTU_START);
    }
    ctx->cb(ec, ctx->data);
}

void nc_keep_alive_handle_packet(const np_error_code ec, uint8_t channelId, uint64_t seq,
                                 np_communication_buffer* buf, uint16_t bufferSize,
                                 struct nc_keep_alive_context* ctx)
{
    uint8_t* ptr = ctx->pl->buf.start(buf);
    if (ec != NABTO_EC_OK) {
        nc_keep_alive_close(ctx, ec);
        return;
    }
    NABTO_LOG_TRACE(LOG, "Received keep alive packet");
    NABTO_LOG_BUF(LOG, ctx->pl->buf.start(buf), bufferSize);
    if (*ptr == AT_KEEP_ALIVE && *(ptr+1) == CT_KEEP_ALIVE_RESPONSE) {
        ptr += NABTO_PACKET_HEADER_SIZE; // skip header
        uint32_t seq = uint32_read(ptr);
        if (seq != 0) {
            // MTU packet
            nc_keep_alive_mtu_handle_response(ctx, seq);
        }
    }
/*    if(ctx->isCli) {
        ctx->pl->dtlsC.async_recv_from(ctx->pl, ctx->cli, AT_KEEP_ALIVE, &nc_keep_alive_recv, ctx);
    } else {
        ctx->pl->dtlsS.async_recv_from(ctx->pl, ctx->srv, AT_KEEP_ALIVE, &nc_keep_alive_recv, ctx);
        } */
}

void nc_keep_alive_stop(struct np_platform* pl,  struct nc_keep_alive_context* ctx)
{
    nc_keep_alive_close(ctx, NABTO_EC_OK);
}

np_error_code nc_keep_alive_async_probe(struct np_platform* pl, struct nc_keep_alive_context* ctx,
                                        uint8_t channelId, keep_alive_callback cb, void* data)
{
    return NABTO_EC_FAILED;
}

np_error_code nc_keep_alive_async_discover_mtu(struct np_platform* pl, struct nc_keep_alive_context* ctx, keep_alive_mtu_callback cb, void* data)
{
    NABTO_LOG_INFO(LOG, "Starting mtu discovery");
    ctx->mtuTries = 0;
    ctx->mtuCb = cb;
    ctx->mtuData = data;
    if (ctx->sending) {
        NABTO_LOG_INFO(LOG, "Already sending, trying again in a bit");
        np_event_queue_post_timed_event(pl, &ctx->mtuDiscEv, 2, &nc_keep_alive_mtu_discover_retry, ctx);
    } else {
        ctx->mtuTries++;
        nc_keep_alive_send_mtu_req(ctx, NC_KEEP_ALIVE_MTU_MAX);
    }
    return NABTO_EC_OK;
}

void nc_keep_alive_mtu_discover_retry(const np_error_code ec, void* data)
{
    struct nc_keep_alive_context* ctx = (struct nc_keep_alive_context*)data;
    if (ctx->mtuTries >= NC_KEEP_ALIVE_MTU_MAX_TRIES) {
        nc_keep_alive_mtu_resolve_discovery(ctx, NABTO_EC_KEEP_ALIVE_TIMEOUT, NC_KEEP_ALIVE_MTU_START);
        return;
    } else if (ctx->sending) {
        NABTO_LOG_INFO(LOG, "Already sending in retry, trying again in a bit");
        np_event_queue_post_timed_event(ctx->pl, &ctx->mtuDiscEv, 2, &nc_keep_alive_mtu_discover_retry, ctx);
    } else {
        ctx->mtuTries++;
        nc_keep_alive_send_mtu_req(ctx, NC_KEEP_ALIVE_MTU_MAX);
    }
}

void nc_keep_alive_send_mtu_req(struct nc_keep_alive_context* ctx, uint16_t size)
{
    uint8_t* start = ctx->pl->buf.start(ctx->buf);
    uint8_t* ptr = start;
    if (size > ctx->pl->buf.size(ctx->buf)) {
        NABTO_LOG_ERROR(LOG, "Tried to send mtu request larger than communication buffer");
        return;
    }

    ctx->sending = true;
    start[0] = (enum application_data_type)AT_KEEP_ALIVE;
    start[1] = (enum keep_alive_content_type)CT_KEEP_ALIVE_REQUEST;
    ptr += 2;
    ptr = uint32_write_forward(ptr, ctx->mtuSeq);
    memset(ptr, 0, size - 6);

    NABTO_LOG_INFO(LOG, "Sending keep alive request for MTU: ");
    NABTO_LOG_BUF(LOG, start, size);
    if(ctx->isCli) {
        ctx->pl->dtlsC.async_send_to(ctx->pl, ctx->cli, 0xff, start, size, &nc_keep_alive_send_cb, ctx);
    } else {
        ctx->sendCtx.buffer = start;
        ctx->sendCtx.bufferSize = size;
        ctx->sendCtx.cb = &nc_keep_alive_send_cb;
        ctx->sendCtx.data = ctx;
        ctx->pl->dtlsS.async_send_data(ctx->pl, ctx->srv, &ctx->sendCtx);
    }
    np_event_queue_post_timed_event(ctx->pl, &ctx->mtuDiscEv, NC_KEEP_ALIVE_MTU_RETRY_INTERVAL, &nc_keep_alive_mtu_discover_retry, ctx);
}

void nc_keep_alive_mtu_resolve_discovery(struct nc_keep_alive_context* ctx, np_error_code ec, uint16_t mtu)
{
    keep_alive_mtu_callback cb = ctx->mtuCb;
    np_event_queue_cancel_timed_event(ctx->pl, &ctx->mtuDiscEv);
    ctx->mtuSeq++;
    ctx->mtuCb = NULL;
    if (cb != NULL) {
        cb(ec, mtu, ctx->mtuData);
    } else {
        NABTO_LOG_ERROR(LOG, "someone made mtu discovery with no callback");
    }
}

void nc_keep_alive_mtu_handle_response(struct nc_keep_alive_context* ctx, uint32_t seq)
{
    if (seq == ctx->mtuSeq) {
        // successful response means max mtu was possible
        nc_keep_alive_mtu_resolve_discovery(ctx, NABTO_EC_OK, NC_KEEP_ALIVE_MTU_MAX);
    }
}
