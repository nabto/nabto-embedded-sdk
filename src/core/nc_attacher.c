
#include "nc_attacher.h"

#include <core/nc_packet.h>
#include <core/nc_coap.h>
#include <platform/np_logging.h>
#include <core/nc_version.h>
#include <core/nc_device.h>

#include <string.h>
#include <stdlib.h>

#include <cbor.h>


#define LOG NABTO_LOG_MODULE_ATTACHER

static const uint32_t ACCESS_DENIED_WAIT_TIME = 3600000; // one hour
static const uint32_t RETRY_WAIT_TIME = 10000; // 10 seconds
static const uint8_t MAX_REDIRECT_FOLLOW = 5;

/******************************
 * local function definitions *
 ******************************/
static void do_close(struct nc_attach_context* ctx);
static void reattach(const np_error_code ec, void* data);
static void resolve_close(void* data);

static void handle_state_change(struct nc_attach_context* ctx);
static void handle_dtls_closed(struct nc_attach_context* ctx);
static void handle_dtls_connected(struct nc_attach_context* ctx);
static void handle_keep_alive_data(struct nc_attach_context* ctx, uint8_t* buffer, uint16_t bufferSize);
static void handle_dtls_access_denied(struct nc_attach_context* ctx);
static np_error_code dtls_packet_sender(uint8_t* buffer, uint16_t bufferSize, np_dtls_cli_send_callback cb, void* data, void* senderData);
static void dtls_data_handler(uint8_t* buffer, uint16_t bufferSize, void* data);
static void dtls_event_handler(enum np_dtls_cli_event event, void* data);

static void dns_resolved_callback(const np_error_code ec, struct np_ip_address* v4Rec, size_t v4RecSize, struct np_ip_address* v6Rec, size_t v6RecSize, void* data);

static void keep_alive_event(const np_error_code ec, void* data);

static void keep_alive_send_req(struct nc_attach_context* ctx);
static void keep_alive_send_response(struct nc_attach_context* ctx, uint8_t* buffer, size_t length);

// attach start request
static void send_attach_start_request(struct nc_attach_context* ctx);
static void coap_attach_start_callback(enum nc_attacher_status status, void* data);

// attach end request
static void send_attach_end_request(struct nc_attach_context* ctx);
static void coap_attach_end_handler(np_error_code ec, void* data);

static void nc_attacher_add_server_connect_token_callback(np_error_code ec, void* userData);

static void coap_attach_failed(struct nc_attach_context* ctx);

/*****************
 * API functions *
 *****************/
np_error_code nc_attacher_init(struct nc_attach_context* ctx, struct np_platform* pl, struct nc_device_context* device, struct nc_coap_client_context* coapClient, nc_attacher_event_listener listener, void* listenerData)
{
    memset(ctx, 0, sizeof(struct nc_attach_context));
    ctx->pl = pl;
    ctx->device = device;
    ctx->coapClient = coapClient;
    ctx->state = NC_ATTACHER_STATE_DNS;
    ctx->moduleState = NC_ATTACHER_MODULE_SETUP;
    ctx->listener = listener;
    ctx->listenerData = listenerData;
    ctx->retryWaitTime = RETRY_WAIT_TIME;
    ctx->accessDeniedWaitTime = ACCESS_DENIED_WAIT_TIME;
    np_error_code ec = pl->dtlsC.create(pl, &ctx->dtls, &dtls_packet_sender, &dtls_data_handler, &dtls_event_handler, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    // Init keep alive with default values,
    nc_keep_alive_init(&ctx->keepAlive, pl);
    return ec;
}
void nc_attacher_deinit(struct nc_attach_context* ctx)
{
    if (ctx->pl != NULL) { // if init was called
        ctx->moduleState = NC_ATTACHER_MODULE_CLOSED;
        if (ctx->state == NC_ATTACHER_STATE_DNS) {
            // ensure that returning DNS resolver will not continue attacher
            do_close(ctx);
        }
        nc_keep_alive_deinit(&ctx->keepAlive);
        if (ctx->udp) {
            nc_udp_dispatch_clear_dtls_cli_context(ctx->udp);
        }
        ctx->pl->dtlsC.destroy(ctx->dtls);


        if (ctx->request != NULL) {
            nabto_coap_client_request_free(ctx->request);
        }

        np_event_queue_cancel_timed_event(ctx->pl, &ctx->reattachTimer);
        np_event_queue_cancel_event(ctx->pl, &ctx->closeEv);
    }
}

void nc_attacher_set_state_listener(struct nc_attach_context* ctx, nc_attacher_state_listener cb, void* data)
{
    ctx->stateListener = cb;
    ctx->stateListenerData = data;
}

np_error_code nc_attacher_set_keys(struct nc_attach_context* ctx, const unsigned char* publicKeyL, size_t publicKeySize, const unsigned char* privateKeyL, size_t privateKeySize)
{
    if (ctx->moduleState != NC_ATTACHER_MODULE_SETUP) {
        return NABTO_EC_INVALID_STATE;
    }
    return ctx->pl->dtlsC.set_keys(ctx->dtls, publicKeyL, publicKeySize, privateKeyL, privateKeySize);
}

np_error_code nc_attacher_set_app_info(struct nc_attach_context* ctx, const char* appName, const char* appVersion)
{
    if (ctx->moduleState != NC_ATTACHER_MODULE_SETUP) {
        return NABTO_EC_INVALID_STATE;
    }
    ctx->appName = appName;
    ctx->appVersion = appVersion;
    return NABTO_EC_OK;
}

np_error_code nc_attacher_set_device_info(struct nc_attach_context* ctx, const char* productId, const char* deviceId)
{
    if (ctx->moduleState != NC_ATTACHER_MODULE_SETUP) {
        return NABTO_EC_INVALID_STATE;
    }
    ctx->productId = productId;
    ctx->deviceId = deviceId;
    return NABTO_EC_OK;
}

np_error_code nc_attacher_set_handshake_timeout(struct nc_attach_context* ctx,
                                                uint32_t minTimeoutMilliseconds, uint32_t maxTimeoutMilliseconds)
{
    struct np_platform* pl = ctx->pl;
    pl->dtlsC.set_handshake_timeout(ctx->dtls, minTimeoutMilliseconds, maxTimeoutMilliseconds);
    return NABTO_EC_OK;
}


np_error_code nc_attacher_start(struct nc_attach_context* ctx, const char* hostname, uint16_t serverPort, struct nc_udp_dispatch_context* udp)
{
    if (ctx->moduleState != NC_ATTACHER_MODULE_SETUP) {
        return NABTO_EC_INVALID_STATE;
    }
    ctx->udp = udp;
    ctx->state = NC_ATTACHER_STATE_DNS;
    ctx->moduleState = NC_ATTACHER_MODULE_RUNNING;
    ctx->hostname = hostname;
    ctx->defaultPort = serverPort;
    ctx->currentPort = serverPort;

    memcpy(ctx->dns, ctx->hostname, strlen(ctx->hostname)+1);
    nc_udp_dispatch_set_dtls_cli_context(ctx->udp, ctx->dtls);
    handle_state_change(ctx);
    return NABTO_EC_OK;
}

np_error_code nc_attacher_async_close(struct nc_attach_context* ctx, nc_attacher_closed_callback callback, void* userData)
{
    ctx->closedCb = callback;
    ctx->closedCbData = userData;
    do_close(ctx);
    return NABTO_EC_OK;
}

/**
 * Stop the attacher module. Stopping differs from close in 2 ways. 1) Stopping has no callback, the module should stop and not expect any further interaction with the caller. 2) It is not required to close an active DTLS connection, it can just be destroyed. Since DTLS create/destroy is paired with attacher_init/deinit, stop should not destroy and might as well close nicely.
 */
np_error_code nc_attacher_stop(struct nc_attach_context* ctx)
{
    do_close(ctx);
    return NABTO_EC_OK;
}

np_error_code nc_attacher_add_server_connect_token(struct nc_attach_context* ctx, const char* token)
{
    char* tokenCopy = strdup(token);
    if (tokenCopy == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    ctx->sctContext.version++;
    if (np_vector_push_back(&ctx->sctContext.scts, tokenCopy) != NABTO_EC_OK)
    {
        free(tokenCopy);
        return NABTO_EC_OUT_OF_MEMORY;
    }

    if (ctx->state == NC_ATTACHER_STATE_ATTACHED) {
        nc_attacher_sct_upload(ctx,  &nc_attacher_add_server_connect_token_callback, NULL);
    }

    return NABTO_EC_OK;
}



np_error_code nc_attacher_is_server_connect_tokens_synchronized(struct nc_attach_context* ctx)
{
    if (ctx->state == NC_ATTACHER_STATE_ATTACHED) {
        if (ctx->sctContext.synchronizedVersion == ctx->sctContext.version) {
            return NABTO_EC_OK;
        } else {
            return NABTO_EC_OPERATION_IN_PROGRESS;
        }
    } else {
        return NABTO_EC_OK;
    }
    // TODO return something else if we are attaching
}

/************************
 * local function impls *
 ************************/

void do_close(struct nc_attach_context* ctx)
{
    if (ctx->moduleState == NC_ATTACHER_MODULE_SETUP) {
        np_event_queue_post(ctx->pl, &ctx->closeEv, &resolve_close, ctx);
        return;
    }
    ctx->moduleState = NC_ATTACHER_MODULE_CLOSED;
    switch(ctx->state) {
        case NC_ATTACHER_STATE_RETRY_WAIT:
        case NC_ATTACHER_STATE_ACCESS_DENIED_WAIT:
            np_event_queue_cancel_timed_event(ctx->pl, &ctx->reattachTimer);
            ctx->state = NC_ATTACHER_STATE_CLOSED;
            handle_state_change(ctx);
            break;
        case NC_ATTACHER_STATE_CLOSED:
            np_event_queue_post(ctx->pl, &ctx->closeEv, &resolve_close, ctx);
            break;
        case NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST:
        case NC_ATTACHER_STATE_ATTACHED:
            ctx->pl->dtlsC.close(ctx->dtls);
            break;
        case NC_ATTACHER_STATE_DNS:
            // dns resolvers can currently not be stopped, for now we just wait for it to finish.
        case NC_ATTACHER_STATE_REDIRECT:
            // When redirecting, we are waiting for DTLS to close before moving to DNS state.
            // Wait for DTLS close to finish
            break;

    }
}

void resolve_close(void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    np_event_queue_cancel_timed_event(ctx->pl, &ctx->reattachTimer);
    np_event_queue_cancel_event(ctx->pl, &ctx->closeEv);
    if (ctx->closedCb) {
        nc_attacher_closed_callback cb = ctx->closedCb;
        ctx->closedCb = NULL;
        cb(ctx->closedCbData);
    }
}

void handle_state_change(struct nc_attach_context* ctx)
{
    NABTO_LOG_TRACE(LOG, "State change to: %u", ctx->state);
    switch(ctx->state) {
        case NC_ATTACHER_STATE_DNS:
        {
            np_error_code ec = ctx->pl->dns.async_resolve(ctx->pl, ctx->dns, &dns_resolved_callback, ctx);
            if (ec) {
                ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
                handle_state_change(ctx);
            }
        }
        break;
        case NC_ATTACHER_STATE_CLOSED:
            np_event_queue_post(ctx->pl, &ctx->closeEv, &resolve_close, ctx);
            break;
        case NC_ATTACHER_STATE_REDIRECT:
            break;
        case NC_ATTACHER_STATE_RETRY_WAIT:
            np_event_queue_post_timed_event(ctx->pl, &ctx->reattachTimer, ctx->retryWaitTime, &reattach, ctx);
            break;
        case NC_ATTACHER_STATE_ACCESS_DENIED_WAIT:
            np_event_queue_post_timed_event(ctx->pl, &ctx->reattachTimer, ctx->accessDeniedWaitTime, &reattach, ctx);
            break;
        case NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST:
            ctx->pl->dtlsC.set_sni(ctx->dtls, ctx->hostname);
            ctx->pl->dtlsC.connect(ctx->dtls);
            break;
        case NC_ATTACHER_STATE_ATTACHED:
            // Nothing to do when attached
            break;
    }
    if (ctx->stateListener != NULL) {
        ctx->stateListener(ctx->state, ctx->stateListenerData);
    }
}


void dns_resolved_callback(const np_error_code ec, struct np_ip_address* v4Rec, size_t v4RecSize, struct np_ip_address* v6Rec, size_t v6RecSize, void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    if (ctx->moduleState == NC_ATTACHER_MODULE_CLOSED) {
        ctx->state = NC_ATTACHER_STATE_CLOSED;
        handle_state_change(ctx);
        return;
    }

    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to resolve attach dispatcher host: (%u)%s", ec, np_error_code_to_string(ec));
        // No DTLS to close so we go directly to RETRY WAIT
        ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
        handle_state_change(ctx);
        return;
    }
    if (v4RecSize == 0 && v6RecSize == 0) {
        NABTO_LOG_ERROR(LOG, "Empty record list");
        // No DTLS to close so we go directly to RETRY WAIT
        ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
        handle_state_change(ctx);
        return;
    }

    memset(ctx->v4BsEps, 0, sizeof(struct nc_attach_endpoint_context[NABTO_MAX_BASESTATION_EPS]));
    memset(ctx->v6BsEps, 0, sizeof(struct nc_attach_endpoint_context[NABTO_MAX_BASESTATION_EPS]));
    ctx->bsEpsTried = 0;
    int i = 0;
    ctx->activeEp = NULL;
    while ( i < v4RecSize && i < NABTO_MAX_BASESTATION_EPS) {
        ctx->v4BsEps[i].ctx = ctx;
        ctx->v4BsEps[i].ep.port = ctx->currentPort;
        memcpy(&ctx->v4BsEps[i].ep.ip, &v4Rec[i], sizeof(struct np_ip_address));
        i++;
    }
    i = 0;
    while ( i < v6RecSize && i < NABTO_MAX_BASESTATION_EPS) {
        ctx->v6BsEps[i].ctx = ctx;
        ctx->v6BsEps[i].ep.port = ctx->currentPort;
        memcpy(&ctx->v6BsEps[i].ep.ip, &v6Rec[i], sizeof(struct np_ip_address));
        i++;
    }

    ctx->state = NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST;
    handle_state_change(ctx);
}

void reattach(const np_error_code ec, void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    if (ctx->moduleState == NC_ATTACHER_MODULE_CLOSED) {
        ctx->state = NC_ATTACHER_STATE_CLOSED;
    } else {
        memcpy(ctx->dns, ctx->hostname, strlen(ctx->hostname)+1);
        ctx->currentPort = ctx->defaultPort;
        ctx->state = NC_ATTACHER_STATE_DNS;
        ctx->redirectAttempts = 0;
    }
    handle_state_change(ctx);
}

void dtls_event_handler(enum np_dtls_cli_event event, void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    if (ctx->moduleState == NC_ATTACHER_MODULE_CLOSED) {
        if (event == NP_DTLS_CLI_EVENT_HANDSHAKE_COMPLETE) {
            ctx->pl->dtlsC.close(ctx->dtls);
        } else {
            ctx->state = NC_ATTACHER_STATE_CLOSED;
            handle_state_change(ctx);
        }
        return;
    }

    if (event == NP_DTLS_CLI_EVENT_HANDSHAKE_COMPLETE) {
        handle_dtls_connected(ctx);
    } else if (event == NP_DTLS_CLI_EVENT_CLOSED) {
        nc_keep_alive_reset(&ctx->keepAlive);
        handle_dtls_closed(ctx);
    } else if (event == NP_DTLS_CLI_EVENT_ACCESS_DENIED) {
        nc_keep_alive_reset(&ctx->keepAlive);
        handle_dtls_access_denied(ctx);
    }
}

void handle_dtls_closed(struct nc_attach_context* ctx)
{
    np_error_code ec = ctx->pl->dtlsC.reset(ctx->dtls);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "tried to reset unclosed DTLS connection");
    }
    // dtls_event_handler() only calls this after moduleState has been check so we dont need to here
    switch(ctx->state) {
        case NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST:
            // DTLS connect failed and dtls was closed, wait to retry
            // Coap request payload could not be set maybe OOM
            // DTLS was closed while waiting for coap response, most likely closed by peer, wait to retry
            ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
            break;
        case NC_ATTACHER_STATE_ATTACHED:
            // DTLS was closed while attached, closed by peer or keep alive timeout. Try reattach
            if (ctx->listener) {
                ctx->listener(NC_DEVICE_EVENT_DETACHED, ctx->listenerData);
            }
            ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
            break;
        case NC_ATTACHER_STATE_REDIRECT:
            if (ctx->redirectAttempts >= MAX_REDIRECT_FOLLOW) {
                ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
            } else {
                // DTLS closed since BS redirected us, resolve new BS.
                ctx->state = NC_ATTACHER_STATE_DNS;
            }
            break;
        case NC_ATTACHER_STATE_ACCESS_DENIED_WAIT:

            // we have reset the dtls context
            break;
        default:
            // states DNS, RETRY_WAIT, CLOSED does not have a DTLS connection which can be closed
            // If this impossible error happens, simply try reattach
            ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
    }
    handle_state_change(ctx);
}

void handle_dtls_connected(struct nc_attach_context* ctx)
{
    if( ctx->pl->dtlsC.get_alpn_protocol(ctx->dtls) == NULL ) {
        NABTO_LOG_ERROR(LOG, "Application Layer Protocol Negotiation failed for Basestation connection");
        ctx->pl->dtlsC.close(ctx->dtls);
        return;
    }
    send_attach_start_request(ctx);
}

void handle_dtls_access_denied(struct nc_attach_context* ctx)
{
    NABTO_LOG_TRACE(LOG, "Received access denied from state: %u", ctx->state);
    np_error_code ec = ctx->pl->dtlsC.reset(ctx->dtls);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "tried to reset unclosed DTLS connection");
    }
    if (ctx->request != NULL) {
        nabto_coap_client_request_free(ctx->request);
        ctx->request = NULL;
    }
    ctx->state = NC_ATTACHER_STATE_ACCESS_DENIED_WAIT;
    handle_state_change(ctx);
}

void send_attach_start_request(struct nc_attach_context* ctx)
{
    np_error_code ec = nc_attacher_attach_start_request(ctx, &coap_attach_start_callback, ctx);
    if (ec != NABTO_EC_OPERATION_STARTED) {
        coap_attach_failed(ctx);
    }
}

void coap_attach_start_callback(enum nc_attacher_status status, void* data)
{
    struct nc_attach_context* ctx = data;

    if (status == NC_ATTACHER_STATUS_ATTACHED) {
        send_attach_end_request(ctx);
    } else if (status == NC_ATTACHER_STATUS_REDIRECT) {
        ctx->state = NC_ATTACHER_STATE_REDIRECT;
        ctx->redirectAttempts++;
        ctx->pl->dtlsC.close(ctx->dtls);
    } else {
        coap_attach_failed(ctx);
    }
}


void send_attach_end_request(struct nc_attach_context* ctx)
{
    np_error_code ec = nc_attacher_attach_end_request(ctx, coap_attach_end_handler, ctx);
    if (ec != NABTO_EC_OPERATION_STARTED) {
        coap_attach_failed(ctx);
    }
}

void coap_attach_failed(struct nc_attach_context* ctx)
{
    ctx->pl->dtlsC.close(ctx->dtls);
    // TODO
}

void coap_attach_end_handler(np_error_code ec, void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;

    if (ec != NABTO_EC_OK) {
        coap_attach_failed(ctx);
        return;
    }

    if (ctx->moduleState == NC_ATTACHER_MODULE_CLOSED) {
        coap_attach_failed(ctx);
        return;
    }

    // start keep alive with default values if above failed
    nc_keep_alive_wait(&ctx->keepAlive, keep_alive_event, ctx);
    ctx->state = NC_ATTACHER_STATE_ATTACHED;
    handle_state_change(ctx);
    if (ctx->listener) {
        ctx->listener(NC_DEVICE_EVENT_ATTACHED, ctx->listenerData);
    }
}

void udp_send_callback(const np_error_code ec, void* data)
{
    struct nc_attach_endpoint_context* ep = (struct nc_attach_endpoint_context*)data;
    ep->ctx->bsEpsTried--;
    if (ep->ctx->activeEp == NULL && ec == NABTO_EC_OK) {
        // First successful responder
        ep->ctx->activeEp = ep;
    }
    if (ep->ctx->senderCb && ep->ctx->bsEpsTried == 0 && ep->ctx->activeEp != NULL) {
        ep->ctx->senderCb(NABTO_EC_OK, ep->ctx->senderCbData);
        ep->ctx->senderCb = NULL;
    } else if (ep->ctx->senderCb && ep->ctx->bsEpsTried == 0) {
        ep->ctx->senderCb(NABTO_EC_UNKNOWN, ep->ctx->senderCbData);
        ep->ctx->senderCb = NULL;
    }
}

np_error_code dtls_packet_sender(uint8_t* buffer, uint16_t bufferSize,
                                 np_dtls_cli_send_callback cb, void* data,
                                 void* senderData)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)senderData;
    if (ctx->activeEp == NULL) {
        // We have yet to find suitable endpoint
        if (ctx->senderCb != NULL) {
            return NABTO_EC_OPERATION_IN_PROGRESS;
        }
        ctx->senderCb = cb;
        ctx->senderCbData = data;
        np_error_code ec = NABTO_EC_UNKNOWN;
        np_error_code ec2 = NABTO_EC_UNKNOWN;
        for (int i = 0; i < NABTO_MAX_BASESTATION_EPS; i++) {
            if (ctx->v4BsEps[i].ctx != NULL) {
                 ec2 = nc_udp_dispatch_async_send_to(ctx->udp, &ctx->v4BsEps[i].ep,
                                                     buffer, bufferSize,
                                                     udp_send_callback, &ctx->v4BsEps[i]);
                 if (ec2 == NABTO_EC_OK) {
                     ctx->bsEpsTried++;
                     ec = ec2;
                 }
            }
            if (ctx->v6BsEps[i].ctx != NULL) {
                 ec2 = nc_udp_dispatch_async_send_to(ctx->udp, &ctx->v6BsEps[i].ep,
                                                     buffer, bufferSize,
                                                     udp_send_callback, &ctx->v6BsEps[i]);
                 if (ec2 == NABTO_EC_OK) {
                     ctx->bsEpsTried++;
                     ec = ec2;
                 }
            }
        }
        // OK if at least one send succeeded UNKNOWN otherwise
        return ec;
    } else {
        return nc_udp_dispatch_async_send_to(ctx->udp, &ctx->activeEp->ep,
                                             buffer, bufferSize,
                                             cb, data);
    }
}

void dtls_data_handler(uint8_t* buffer, uint16_t bufferSize, void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;

    if (bufferSize < 1) {
        return;
    }

    uint8_t applicationType = *buffer;
    if (applicationType >= AT_COAP_START && applicationType <= AT_COAP_END) {
        NABTO_LOG_TRACE(LOG, "Received COAP packet");
        nc_coap_client_handle_packet(ctx->coapClient, buffer, bufferSize, ctx->dtls);
    } else if (applicationType == AT_KEEP_ALIVE) {
        handle_keep_alive_data(ctx, buffer, bufferSize);
    } else {
        NABTO_LOG_ERROR(LOG, "unknown application data type: %u", applicationType);
    }
}

void keep_alive_event(const np_error_code ec, void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    struct np_platform* pl = ctx->pl;

    uint32_t recvCount;
    uint32_t sentCount;

    if (ec != NABTO_EC_OK) {
        // event probably cancelled
        return;
    } else {
        pl->dtlsC.get_packet_count(ctx->dtls, &recvCount, &sentCount);
        enum nc_keep_alive_action action = nc_keep_alive_should_send(&ctx->keepAlive, recvCount, sentCount);
        switch(action) {
            case DO_NOTHING:
                nc_keep_alive_wait(&ctx->keepAlive, keep_alive_event, ctx);
                break;
            case SEND_KA:
                keep_alive_send_req(ctx);
                nc_keep_alive_wait(&ctx->keepAlive, keep_alive_event, ctx);
                break;
            case KA_TIMEOUT:
                ctx->pl->dtlsC.close(ctx->dtls);
                break;
        }
    }
}

void handle_keep_alive_data(struct nc_attach_context* ctx, uint8_t* buffer, uint16_t bufferSize)
{
    uint8_t* start = buffer;
    if (bufferSize < 2) {
        return;
    }
    uint8_t contentType = start[1];
    if (contentType == CT_KEEP_ALIVE_REQUEST) {
        keep_alive_send_response(ctx, start, bufferSize);
    } else if (contentType == CT_KEEP_ALIVE_RESPONSE) {
        // Do nothing, the fact that we did get a packet increases the vital counters.
    }
}

void keep_alive_send_req(struct nc_attach_context* ctx)
{
    struct np_platform* pl = ctx->pl;
    struct np_dtls_cli_send_context* sendCtx = &ctx->keepAliveSendCtx;

    nc_keep_alive_create_request(&ctx->keepAlive, &sendCtx->buffer, (size_t*)&sendCtx->bufferSize);
    sendCtx->cb = &nc_keep_alive_packet_sent;
    sendCtx->data = &ctx->keepAlive;

    pl->dtlsC.async_send_data(ctx->dtls, sendCtx);
}

void keep_alive_send_response(struct nc_attach_context* ctx, uint8_t* buffer, size_t length)
{
    struct np_platform* pl = ctx->pl;
    struct np_dtls_cli_send_context* sendCtx = &ctx->keepAliveSendCtx;
    if(nc_keep_alive_handle_request(&ctx->keepAlive, buffer, length, &sendCtx->buffer, (size_t*)&sendCtx->bufferSize)) {
        sendCtx->cb = &nc_keep_alive_packet_sent;
        sendCtx->data = &ctx->keepAlive;
        pl->dtlsC.async_send_data(ctx->dtls, sendCtx);
    }
}


void nc_attacher_add_server_connect_token_callback(np_error_code ec, void* userData)
{
    // do nothing
}
