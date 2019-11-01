
#include "nc_attacher.h"

#include <core/nc_packet.h>
#include <platform/np_logging.h>
#include <core/nc_version.h>
#include <core/nc_device.h>

#include <string.h>

#include <cbor.h>

#define LOG NABTO_LOG_MODULE_ATTACHER

const char* attachPath[2] = {"device", "attach"};

/******************************
 * local function definitions *
 ******************************/
static void do_close(struct nc_attach_context* ctx);
static void reattach(const np_error_code ec, void* data);
static uint32_t get_reattach_time(struct nc_attach_context* ctx);
static void resolve_close(void* data);
static void send_attach_request(struct nc_attach_context* ctx);

static void handle_state_change(struct nc_attach_context* ctx);
static void handle_dtls_closed(struct nc_attach_context* ctx);
static void handle_dtls_connected(struct nc_attach_context* ctx);
static void handle_device_attached_response(struct nc_attach_context* ctx, CborValue* root, struct nabto_coap_client_request* request);
static void handle_device_redirect_response(struct nc_attach_context* ctx, CborValue* root);
static void handle_keep_alive_data(struct nc_attach_context* ctx, uint8_t* buffer, uint16_t bufferSize);

static void dtls_packet_sender(bool activeChannel, uint8_t* buffer, uint16_t bufferSize, np_dtls_cli_send_callback cb, void* data, void* senderData);
static void dtls_data_handler(uint8_t channelId, uint64_t sequence, uint8_t* buffer, uint16_t bufferSize, void* data);
static void dtls_event_handler(enum np_dtls_cli_event event, void* data);

static void dns_resolved_callback(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data);

static void coap_response_failed(struct nc_attach_context* ctx, struct nabto_coap_client_request* request);
static void coap_request_handler(struct nabto_coap_client_request* request, void* data);

static void keep_alive_event(const np_error_code ec, void* data);

static void keep_alive_send_req(struct nc_attach_context* ctx);
static void keep_alive_send_response(struct nc_attach_context* ctx, uint8_t* buffer, size_t length);



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
    nc_keep_alive_deinit(&ctx->keepAlive);
    ctx->pl->dtlsC.destroy(ctx->dtls);

    if (ctx->udp != NULL) {
        nc_udp_dispatch_clear_dtls_cli_context(ctx->udp);
    }
    // cleanup/close dtls connections etc.
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

np_error_code nc_attacher_start(struct nc_attach_context* ctx, const char* hostname, uint16_t serverPort, struct nc_udp_dispatch_context* udp)
{
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
            np_event_queue_cancel_timed_event(ctx->pl, &ctx->reattachTimer);
            ctx->state = NC_ATTACHER_STATE_CLOSED;
            handle_state_change(ctx);
            break;
        case NC_ATTACHER_STATE_CLOSED:
            np_event_queue_post(ctx->pl, &ctx->closeEv, &resolve_close, ctx);
            break;
        case NC_ATTACHER_STATE_DTLS_CONNECT:
        case NC_ATTACHER_STATE_COAP_ATTACH_REQUEST:
        case NC_ATTACHER_STATE_ATTACHED:
            ctx->pl->dtlsC.close(ctx->pl, ctx->dtls);
            break;
        case NC_ATTACHER_STATE_DNS:
            // dns resolvers can currently not be stopped, for now we just wait for it to finish.
        case NC_ATTACHER_STATE_PREPARE_RETRY:
            // we are already closing the DTLS connection, just wait for it to finish
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
    switch(ctx->state) {
        case NC_ATTACHER_STATE_DNS:
            ctx->pl->dns.async_resolve(ctx->pl, ctx->dns, &dns_resolved_callback, ctx);
            break;
        case NC_ATTACHER_STATE_CLOSED:
            np_event_queue_post(ctx->pl, &ctx->closeEv, &resolve_close, ctx);
            break;
        case NC_ATTACHER_STATE_REDIRECT:
        case NC_ATTACHER_STATE_PREPARE_RETRY:
            ctx->pl->dtlsC.close(ctx->pl, ctx->dtls);
            break;
        case NC_ATTACHER_STATE_RETRY_WAIT:
            np_event_queue_post_timed_event(ctx->pl, &ctx->reattachTimer, get_reattach_time(ctx), &reattach, ctx);
            break;
        case NC_ATTACHER_STATE_DTLS_CONNECT:
            ctx->pl->dtlsC.set_sni(ctx->dtls, ctx->hostname);
            ctx->pl->dtlsC.connect(ctx->dtls);
            break;
        case NC_ATTACHER_STATE_COAP_ATTACH_REQUEST:
            send_attach_request(ctx);
            break;
        case NC_ATTACHER_STATE_ATTACHED:
            // Nothing to do when attached
            break;
    }
}

void dns_resolved_callback(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data)
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
    if (recSize == 0) {
        NABTO_LOG_ERROR(LOG, "Empty record list");
        // No DTLS to close so we go directly to RETRY WAIT
        ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
        handle_state_change(ctx);
        return;
    }
    int i = 0;
    // TODO: If recSize > MAX_BS_EPS, consider picking records which matches the supported protocol IPv4/IPv6
    while ( i < recSize && i < NABTO_MAX_BASESTATION_EPS) {
        ctx->bsEps[i].port = ctx->currentPort;
        memcpy(&ctx->bsEps[i].ip, &rec[i], sizeof(struct np_ip_address));
        i++;
    }

    ctx->state = NC_ATTACHER_STATE_DTLS_CONNECT;
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
    }
    handle_state_change(ctx);
}

void dtls_event_handler(enum np_dtls_cli_event event, void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    if (event == NP_DTLS_CLI_EVENT_HANDSHAKE_COMPLETE) {
        handle_dtls_connected(ctx);
    } else if (event == NP_DTLS_CLI_EVENT_CLOSED) {
        nc_keep_alive_reset(&ctx->keepAlive);
        if (ctx->moduleState == NC_ATTACHER_MODULE_CLOSED) {
            ctx->state = NC_ATTACHER_STATE_CLOSED;
            handle_state_change(ctx);
        } else {
            handle_dtls_closed(ctx);
        }
    }
}

void handle_dtls_closed(struct nc_attach_context* ctx)
{
    // dtls_event_handler() only calls this after moduleState has been check so we dont need to here
    switch(ctx->state) {
        case NC_ATTACHER_STATE_ATTACHED:
            // DTLS was closed while attached, most likely closed by peer, wait to retry
            if (ctx->listener) {
                ctx->listener(NC_DEVICE_EVENT_DETACHED, ctx->listenerData);
            }
        case NC_ATTACHER_STATE_DTLS_CONNECT:
            // DTLS connect failed and dtls was closed, wait to retry
        case NC_ATTACHER_STATE_COAP_ATTACH_REQUEST:
            // DTLS was closed while waiting for coap response, most likely closed by peer, wait to retry
        case NC_ATTACHER_STATE_PREPARE_RETRY:
            // Previous DTLS is now closed, wait to retry
            ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
            break;
        case NC_ATTACHER_STATE_REDIRECT:
            // DTLS closed since BS redirected us, resolve new BS.
            ctx->state = NC_ATTACHER_STATE_DNS;
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
        ctx->state = NC_ATTACHER_STATE_PREPARE_RETRY;
        handle_state_change(ctx);
        return;
    }
    ctx->state = NC_ATTACHER_STATE_COAP_ATTACH_REQUEST;
    handle_state_change(ctx);
}

void send_attach_request(struct nc_attach_context* ctx)
{
    struct nabto_coap_client_request* req;
    uint8_t buffer[512];

    req = nabto_coap_client_request_new(nc_coap_client_get_client(ctx->coapClient),
                                        NABTO_COAP_METHOD_POST,
                                        2, attachPath,
                                        &coap_request_handler,
                                        ctx, ctx->dtls);
    nabto_coap_client_request_set_content_format(req, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);

    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, buffer, 512, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "NabtoVersion");
    cbor_encode_text_stringz(&map, NABTO_VERSION);

    cbor_encode_text_stringz(&map, "AppName");
    cbor_encode_text_stringz(&map, ctx->appName);

    cbor_encode_text_stringz(&map, "AppVersion");
    cbor_encode_text_stringz(&map, ctx->appVersion);

    cbor_encode_text_stringz(&map, "ProductId");
    cbor_encode_text_stringz(&map, ctx->productId);

    cbor_encode_text_stringz(&map, "DeviceId");
    cbor_encode_text_stringz(&map, ctx->deviceId);

    cbor_encoder_close_container(&encoder, &map);

    if (cbor_encoder_get_extra_bytes_needed(&encoder) != 0) {
        // TODO impossible error
    }

    size_t used = cbor_encoder_get_buffer_size(&encoder, buffer);

    NABTO_LOG_TRACE(LOG, "Sending attach CoAP Request:");

    nabto_coap_client_request_set_payload(req, buffer, used);
    nabto_coap_client_request_send(req);
}

void coap_request_handler(struct nabto_coap_client_request* request, void* data)
{
    NABTO_LOG_TRACE(LOG, "Received basestation CoAP attach response");
    const uint8_t* start;
    size_t bufferSize;

    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    if (ctx->moduleState == NC_ATTACHER_MODULE_CLOSED) {
        // coap_response_failed will set retry state which will close DTLS, once closed it will close completely
        coap_response_failed(ctx, request);
        return;
    }
    struct nabto_coap_client_response* res = nabto_coap_client_request_get_response(request);
    if (!res) {
        // Request failed
        NABTO_LOG_ERROR(LOG, "Coap request failed, no response");
        coap_response_failed(ctx, request);
        return;
    }
    uint16_t resCode = nabto_coap_client_response_get_code(res);
    if (resCode != 201) {
        NABTO_LOG_ERROR(LOG, "BS returned CoAP error code: %d", resCode);
        coap_response_failed(ctx, request);
        return;
    }
    if (!nabto_coap_client_response_get_payload(res, &start, &bufferSize)) {
        NABTO_LOG_ERROR(LOG, "No payload in CoAP response");
        coap_response_failed(ctx, request);
        return;
    }

    CborParser parser;
    CborValue root;
    CborValue status;

    cbor_parser_init(start, bufferSize, 0, &parser, &root);

    if (!cbor_value_is_map(&root)) {
        NABTO_LOG_ERROR(LOG, "Invalid coap response format");
        coap_response_failed(ctx, request);
        return;
    }

    cbor_value_map_find_value(&root, "Status", &status);

    if (!cbor_value_is_unsigned_integer(&status)) {
        NABTO_LOG_ERROR(LOG, "Status not an integer");
        coap_response_failed(ctx, request);
        return;
    }

    uint64_t s;
    cbor_value_get_uint64(&status, &s);

    if (s == ATTACH_STATUS_ATTACHED) {
        // this will free the request
        handle_device_attached_response(ctx, &root, request);
    } else if (s == ATTACH_STATUS_REDIRECT) {
        handle_device_redirect_response(ctx, &root);
        // coap_response_failed() will free req if we return before this
        nabto_coap_client_request_free(request);
    } else {
        NABTO_LOG_ERROR(LOG, "Status not recognized");
        coap_response_failed(ctx, request);
        return;
    }
}

void coap_response_failed(struct nc_attach_context* ctx, struct nabto_coap_client_request* request)
{
    nabto_coap_client_request_free(request);
    ctx->state = NC_ATTACHER_STATE_PREPARE_RETRY;
    handle_state_change(ctx);
}

void handle_device_attached_response(struct nc_attach_context* ctx, CborValue* root, struct nabto_coap_client_request* request)
{
    CborValue keepAlive;
    cbor_value_map_find_value(root, "KeepAlive", &keepAlive);
    if (cbor_value_is_map(&keepAlive)) {
        CborValue interval;
        CborValue retryInterval;
        CborValue maxRetries;

        cbor_value_map_find_value(&keepAlive, "Interval", &interval);
        cbor_value_map_find_value(&keepAlive, "RetryInterval", &retryInterval);
        cbor_value_map_find_value(&keepAlive, "MaxRetries", &maxRetries);

        if (cbor_value_is_unsigned_integer(&interval) &&
            cbor_value_is_unsigned_integer(&retryInterval) &&
            cbor_value_is_unsigned_integer(&maxRetries))
        {
            uint64_t i;
            uint64_t ri;
            uint64_t mr;
            cbor_value_get_uint64(&interval, &i);
            cbor_value_get_uint64(&retryInterval, &ri);
            cbor_value_get_uint64(&maxRetries, &mr);

            NABTO_LOG_TRACE(LOG, "starting ka with int: %u, retryInt: %u, maxRetries: %u", i, ri, mr);
            nc_keep_alive_set_settings(&ctx->keepAlive, i, ri, mr);
        }
    }
    // free the request before calling listener in case the listener deinits coap
    nabto_coap_client_request_free(request);
    // start keep alive with default values if above failed
    nc_keep_alive_wait(&ctx->keepAlive, keep_alive_event, ctx);
    ctx->state = NC_ATTACHER_STATE_ATTACHED;
    handle_state_change(ctx);
    if (ctx->listener) {
        ctx->listener(NC_DEVICE_EVENT_ATTACHED, ctx->listenerData);
    }
}

void handle_device_redirect_response(struct nc_attach_context* ctx, CborValue* root)
{
    CborValue host;
    CborValue port;
    CborValue fingerprint;

    cbor_value_map_find_value(root, "Host", &host);
    cbor_value_map_find_value(root, "Port", &port);
    cbor_value_map_find_value(root, "Fingerprint", &fingerprint);


    if (cbor_value_is_text_string(&host) &&
        cbor_value_is_unsigned_integer(&port) &&
        cbor_value_is_byte_string(&fingerprint))
    {
        uint64_t p;
        size_t hostLength;
        cbor_value_get_string_length(&host, &hostLength);
        cbor_value_get_uint64(&port, &p);

        // TODO how small can valid hostname be ?
        if (hostLength < 1 || hostLength > 256) {
            NABTO_LOG_ERROR(LOG, "Redirect response had invalid hostname length: %u", hostLength);
            ctx->state = NC_ATTACHER_STATE_PREPARE_RETRY;
            handle_state_change(ctx);
            return;
        }

        cbor_value_copy_text_string(&host, ctx->dns, &hostLength, NULL);
        ctx->currentPort = p;

    } else {
        NABTO_LOG_ERROR(LOG, "Redirect response not understood");
        ctx->state = NC_ATTACHER_STATE_PREPARE_RETRY;
        handle_state_change(ctx);
        return;
    }
    ctx->state = NC_ATTACHER_STATE_REDIRECT;
    handle_state_change(ctx);
    return;
}

void dtls_packet_sender(bool activeChannel,
                        uint8_t* buffer, uint16_t bufferSize,
                        np_dtls_cli_send_callback cb, void* data,
                        void* senderData)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)senderData;
    // TODO handle error
    // TODO if connecting try all endpoints
    nc_udp_dispatch_async_send_to(ctx->udp, &ctx->bsEps[0],
                                  buffer, bufferSize,
                                  cb, data);
}

void dtls_data_handler(uint8_t channelId, uint64_t sequence,
                       uint8_t* buffer, uint16_t bufferSize, void* data)
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
                ctx->state = NC_ATTACHER_STATE_PREPARE_RETRY;
                handle_state_change(ctx);
                break;
        }
    }
}

uint32_t get_reattach_time(struct nc_attach_context* ctx)
{
    uint32_t ms;
    if (ctx->attachAttempts >= 19) { // 2^19s > 12h
        ms = 43200000; // 12h
    } else {
        ms = 2 << ctx->attachAttempts; // 2sec^n
        ms = ms * 1000; // s to ms
        ctx->attachAttempts++;
    }
    NABTO_LOG_INFO(LOG, "returning reattach time: %i, attachAttempts: %i", ms, ctx->attachAttempts);
    return ms;
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

    pl->dtlsC.async_send_data(pl, ctx->dtls, sendCtx);
}

void keep_alive_send_response(struct nc_attach_context* ctx, uint8_t* buffer, size_t length)
{
    struct np_platform* pl = ctx->pl;
    struct np_dtls_cli_send_context* sendCtx = &ctx->keepAliveSendCtx;
    if(nc_keep_alive_handle_request(&ctx->keepAlive, buffer, length, &sendCtx->buffer, (size_t*)&sendCtx->bufferSize)) {
        sendCtx->cb = &nc_keep_alive_packet_sent;
        sendCtx->data = &ctx->keepAlive;
        pl->dtlsC.async_send_data(pl, ctx->dtls, sendCtx);
    }
}
