
#include "nc_attacher.h"

#include <core/nc_packet.h>
#include <platform/np_logging.h>
#include <core/nc_version.h>
#include <core/nc_device.h>

#include <string.h>

#include <cbor.h>

#define LOG NABTO_LOG_MODULE_ATTACHER

//struct nc_attach_context ctx;

const char* attachPath[2] = {"device", "attach"};

void nc_attacher_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data);
void nc_attacher_dtls_conn_ok(struct nc_attach_context* ctx);
void nc_attacher_dtls_closed_cb(const np_error_code ec, void* data);
void nc_attacher_coap_request_handler(struct nabto_coap_client_request* request, void* userData);
void nc_attacher_dtls_recv_cb(const np_error_code ec, uint8_t channelId, uint64_t sequence,
                              uint8_t* buf, uint16_t bufferSize, void* data);
static void nc_attacher_coap_request_handler2(struct nabto_coap_client_request* request, void* data);


void nc_attacher_handle_keep_alive(struct nc_attach_context* ctx, uint8_t* buffer, uint16_t bufferSize);
void nc_attacher_keep_alive_start(struct nc_attach_context* ctx);
void nc_attacher_keep_alive_event(const np_error_code ec, void* data);
void nc_attacher_keep_alive_send_req(struct nc_attach_context* ctx);
void nc_attacher_keep_alive_send_response(struct nc_attach_context* ctx, uint8_t* buffer, size_t length);
void nc_attacher_keep_alive_packet_sent(const np_error_code ec, void* data);

void nc_attacher_dtls_sender(bool activeChannel,
                             uint8_t* buffer, uint16_t bufferSize,
                             np_dtls_cli_send_callback cb, void* data,
                             void* senderData);
void nc_attacher_dtls_event_handler(enum np_dtls_cli_event event, void* data);
void nc_attacher_dtls_data_handler(uint8_t channelId, uint64_t sequence,
                                   uint8_t* buffer, uint16_t bufferSize, void* data);

static void handle_device_attached_response(struct nc_attach_context* ctx, CborValue* root);
static void handle_device_redirect_response(struct nc_attach_context* ctx, CborValue* root);
static void coap_response_failed(struct nc_attach_context* ctx);


void nc_attacher_init(struct nc_attach_context* ctx, struct np_platform* pl, struct nc_device_context* device, struct nc_coap_client_context* coapClient)
{
    memset(ctx, 0, sizeof(struct nc_attach_context));
    ctx->pl = pl;
    ctx->device = device;
    pl->dtlsC.create(pl, &ctx->dtls, &nc_attacher_dtls_sender, &nc_attacher_dtls_data_handler, &nc_attacher_dtls_event_handler, ctx);
    ctx->coapClient = coapClient;

    nc_keep_alive_init(&ctx->keepAlive, pl, 30000, 2000, 15);
}
void nc_attacher_deinit(struct nc_attach_context* ctx)
{
    ctx->pl->dtlsC.destroy(ctx->dtls);
    if (ctx->udp != NULL) {
        nc_udp_dispatch_clear_dtls_cli_context(ctx->udp);
    }
    // cleanup/close dtls connections etc.
}

np_error_code nc_attacher_set_keys(struct nc_attach_context* ctx, const unsigned char* publicKeyL, size_t publicKeySize, const unsigned char* privateKeyL, size_t privateKeySize)
{
    return ctx->pl->dtlsC.set_keys(ctx->dtls, publicKeyL, publicKeySize, privateKeyL, privateKeySize);
}

void nc_attacher_handle_keep_alive(struct nc_attach_context* ctx, uint8_t* buffer, uint16_t bufferSize)
{
    uint8_t* start = buffer;
    if (bufferSize < 2) {
        return;
    }
    uint8_t contentType = start[1];
    if (contentType == CT_KEEP_ALIVE_REQUEST) {
        nc_attacher_keep_alive_send_response(ctx, start, bufferSize);
    } else if (contentType == CT_KEEP_ALIVE_RESPONSE) {
        // Do nothing, the fact that we did get a packet increases the vital counters.
    }
}

void nc_attacher_keep_alive_start(struct nc_attach_context* ctx)
{
    // TODO get ka settings from attach
    ctx->keepAlive.kaInterval = 30000;
    ctx->keepAlive.kaRetryInterval = 2000;
    ctx->keepAlive.kaMaxRetries = 15;
    nc_keep_alive_wait(&ctx->keepAlive, nc_attacher_keep_alive_event, ctx);
}

void nc_attacher_keep_alive_event(const np_error_code ec, void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    struct np_platform* pl = ctx->pl;

    uint32_t recvCount;
    uint32_t sentCount;
    pl->dtlsC.get_packet_count(ctx->dtls, &recvCount, &sentCount);

    if (ec != NABTO_EC_OK) {
        // event probably cancelled
        return;
    } else {
        enum nc_keep_alive_action action = nc_keep_alive_should_send(&ctx->keepAlive, recvCount, sentCount);
        switch(action) {
            case DO_NOTHING:
                nc_keep_alive_wait(&ctx->keepAlive, nc_attacher_keep_alive_event, ctx);
                break;
            case SEND_KA:
                nc_attacher_keep_alive_send_req(ctx);
                nc_keep_alive_wait(&ctx->keepAlive, nc_attacher_keep_alive_event, ctx);
                break;
            case KA_TIMEOUT:
                // TODO close connection

                break;
            case DTLS_ERROR:
                return;
        }
    }
}

void nc_attacher_keep_alive_send_req(struct nc_attach_context* ctx)
{
    struct np_platform* pl = ctx->pl;
    if (ctx->keepAlive.isSending) {
        return;
    }
    uint8_t* begin = ctx->keepAlive.sendBuffer;
    uint8_t* ptr = begin;
    *ptr = AT_KEEP_ALIVE; ptr++;
    *ptr = CT_KEEP_ALIVE_REQUEST; ptr++;
    memset(ptr, 0, 16); ptr += 16;

    ctx->keepAlive.isSending = true;

    struct np_dtls_cli_send_context* sendCtx = &ctx->keepAliveSendCtx;
    sendCtx->buffer = begin;
    sendCtx->bufferSize = 18;
    sendCtx->cb = &nc_keep_alive_packet_sent;
    sendCtx->data = &ctx->keepAlive;

    pl->dtlsC.async_send_data(pl, ctx->dtls, sendCtx);
}

void nc_attacher_keep_alive_send_response(struct nc_attach_context* ctx, uint8_t* buffer, size_t length)
{
    struct np_platform* pl = ctx->pl;
    if (length < 18) {
        return;
    }
    if (ctx->keepAlive.isSending) {
        return;
    }
    uint8_t* begin = ctx->keepAlive.sendBuffer;
    uint8_t* ptr = begin;
    *ptr = AT_KEEP_ALIVE; ptr++;
    *ptr = CT_KEEP_ALIVE_RESPONSE; ptr++;
    memcpy(ptr, buffer+2, 16);
    ctx->keepAlive.isSending = true;

    struct np_dtls_cli_send_context* sendCtx = &ctx->keepAliveSendCtx;
    sendCtx->buffer = begin;
    sendCtx->bufferSize = 18;
    sendCtx->cb = &nc_keep_alive_packet_sent;
    sendCtx->data = &ctx->keepAlive;

    pl->dtlsC.async_send_data(pl, ctx->dtls, sendCtx);
}


void nc_attacher_dtls_sender(bool activeChannel,
                             uint8_t* buffer, uint16_t bufferSize,
                             np_dtls_cli_send_callback cb, void* data,
                             void* senderData)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)senderData;
    nc_udp_dispatch_async_send_to(ctx->udp,
                                  &ctx->sendCtx, &ctx->ep,
                                  buffer, bufferSize,
                                  cb, data);
}



void nc_attacher_dtls_event_handler(enum np_dtls_cli_event event, void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    if (event == NP_DTLS_CLI_EVENT_HANDSHAKE_COMPLETE) {
        nc_attacher_dtls_conn_ok(ctx);
        // start keep alive
    } else if (event == NP_DTLS_CLI_EVENT_CLOSED) {
        if (ctx->detachCb) {
            nc_detached_callback cb = ctx->detachCb;
            ctx->detachCb = NULL;
            cb(NABTO_EC_FAILED, ctx->detachCbData);
        }
    }
}

void nc_attacher_dtls_data_handler(uint8_t channelId, uint64_t sequence,
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
        nc_attacher_handle_keep_alive(ctx, buffer, bufferSize);
    } else {
        NABTO_LOG_ERROR(LOG, "unknown application data type: %u", applicationType);
    }
}


np_error_code nc_attacher_async_attach(struct nc_attach_context* ctx, struct np_platform* pl,
                                       const struct nc_attach_parameters* params,
                                       nc_attached_callback cb, void* data)
{
    ctx->pl = pl;
    ctx->cb = cb;
    ctx->cbData = data;
    ctx->params = params;
    ctx->udp = params->udp;
    ctx->state = NC_ATTACHER_RESOLVING_DNS;
    ctx->detaching = false;

    memcpy(ctx->dns, ctx->params->hostname, strlen(ctx->params->hostname)+1);
    ctx->pl->dns.async_resolve(ctx->pl, ctx->dns, &nc_attacher_dns_cb, ctx);
    nc_udp_dispatch_set_dtls_cli_context(ctx->udp, ctx->dtls);
    return NABTO_EC_OK;
}


void nc_attacher_dns_cb(const np_error_code ec, struct np_ip_address* rec, size_t recSize, void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    struct np_platform* pl = ctx->pl;
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to resolve attach dispatcher host");
        ctx->cb(ec, ctx->cbData);
        return;
    }
    if (recSize == 0 || ctx->detaching) {
        NABTO_LOG_ERROR(LOG, "Empty record list or detaching");
        ctx->cb(NABTO_EC_FAILED, ctx->cbData);
        return;
    }
    ctx->state = NC_ATTACHER_CONNECTING_TO_BS;
    ctx->ep.port = ctx->device->serverPort;
    // TODO: Pick a record which matches the supported protocol IPv4/IPv6 ?
    for (int i = 0; i < recSize; i++) {
    }
    memcpy(&ctx->ep.ip, &rec[0], sizeof(struct np_ip_address));

    pl->dtlsC.set_sni(ctx->dtls, ctx->params->hostname);
    pl->dtlsC.connect(ctx->dtls);
}


void nc_attacher_dtls_conn_ok(struct nc_attach_context* ctx)
{
    uint8_t buffer[512];
    struct nabto_coap_client_request* req;

    if( ctx->pl->dtlsC.get_alpn_protocol(ctx->dtls) == NULL ) {
        NABTO_LOG_ERROR(LOG, "Application Layer Protocol Negotiation failed for Basestation connection");
        ctx->pl->dtlsC.async_close(ctx->pl, ctx->dtls, &nc_attacher_dtls_closed_cb, ctx);
        ctx->cb(NABTO_EC_ALPN_FAILED, ctx->cbData);
        return;
    }
    ctx->state = NC_ATTACHER_CONNECTED_TO_BS;

    req = nabto_coap_client_request_new(nc_coap_client_get_client(ctx->coapClient),
                                        NABTO_COAP_METHOD_POST,
                                        2, attachPath,
                                        &nc_attacher_coap_request_handler,
                                        ctx, ctx->dtls);
    nabto_coap_client_request_set_content_format(req, NABTO_COAP_CONTENT_FORMAT_APPLICATION_CBOR);

    CborEncoder encoder;
    CborEncoder map;
    cbor_encoder_init(&encoder, buffer, 512, 0);
    cbor_encoder_create_map(&encoder, &map, CborIndefiniteLength);

    cbor_encode_text_stringz(&map, "NabtoVersion");
    cbor_encode_text_stringz(&map, NABTO_VERSION);

    cbor_encode_text_stringz(&map, "AppName");
    cbor_encode_text_stringz(&map, ctx->params->appName);

    cbor_encode_text_stringz(&map, "AppVersion");
    cbor_encode_text_stringz(&map, ctx->params->appVersion);

    cbor_encode_text_stringz(&map, "ProductId");
    cbor_encode_text_stringz(&map, ctx->device->productId);

    cbor_encode_text_stringz(&map, "DeviceId");
    cbor_encode_text_stringz(&map, ctx->device->deviceId);

    cbor_encoder_close_container(&encoder, &map);

    if (cbor_encoder_get_extra_bytes_needed(&encoder) != 0) {
        // TODO impossible error
    }

    size_t used = cbor_encoder_get_buffer_size(&encoder, buffer);

    NABTO_LOG_TRACE(LOG, "Sending attach CoAP Request:");

    nabto_coap_client_request_set_payload(req, buffer, used);
    nabto_coap_client_request_send(req);
}

void nc_attacher_dtls_closed_cb(const np_error_code ec, void* data)
{
    NABTO_LOG_INFO(LOG, "Dtls connection closed callback");
}

void nc_attacher_coap_request_handler(struct nabto_coap_client_request* request, void* data)
{
    nc_attacher_coap_request_handler2(request, data);
    nabto_coap_client_request_free(request);
}

void handle_device_attached_response(struct nc_attach_context* ctx, CborValue* root)
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
            // TODO
            //ctx->pl->dtlsC.start_keep_alive(ctx->dtls, interval, retryInt, maxRetries);
        }
    }
    nc_attacher_keep_alive_start(ctx);
    ctx->state = NC_ATTACHER_ATTACHED;
    ctx->cb(NABTO_EC_OK, ctx->cbData);
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

        // TODO if (hostLength < )

        cbor_value_copy_text_string(&host, ctx->dns, &hostLength, NULL);
        ctx->ep.port = p;

    } else {
        NABTO_LOG_ERROR(LOG, "Redirect response not understood");
        coap_response_failed(ctx);
        return;
    }
    ctx->pl->dtlsC.async_close(ctx->pl, ctx->dtls, &nc_attacher_dtls_closed_cb, ctx);
    ctx->pl->dns.async_resolve(ctx->pl, ctx->dns, &nc_attacher_dns_cb, ctx);
    return;
}

void coap_response_failed(struct nc_attach_context* ctx)
{
    ctx->pl->dtlsC.async_close(ctx->pl, ctx->dtls, &nc_attacher_dtls_closed_cb, ctx);
    if (ctx->detachCb) {
        nc_detached_callback cb = ctx->detachCb;
        ctx->detachCb = NULL;
        cb(NABTO_EC_FAILED, ctx->detachCbData);
    }
}

void nc_attacher_coap_request_handler2(struct nabto_coap_client_request* request, void* data)
{
    NABTO_LOG_INFO(LOG, "Received CoAP response");
    const uint8_t* start;
    size_t bufferSize;

    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    struct nabto_coap_client_response* res = nabto_coap_client_request_get_response(request);
    if (!res) {
        // Request failed
        NABTO_LOG_ERROR(LOG, "Coap request failed, no response");
        coap_response_failed(ctx);
        return;
    }
    uint16_t resCode = nabto_coap_client_response_get_code(res);
    if (resCode != 201) {
        NABTO_LOG_ERROR(LOG, "BS returned CoAP error code: %d", resCode);
        coap_response_failed(ctx);
        return;
    }
    if (!nabto_coap_client_response_get_payload(res, &start, &bufferSize)) {
        NABTO_LOG_ERROR(LOG, "No payload in CoAP response");
        coap_response_failed(ctx);
        return;
    }

    CborParser parser;
    CborValue root;
    CborValue keepAlive;
    CborValue status;

    cbor_parser_init(start, bufferSize, 0, &parser, &root);

    if (!cbor_value_is_map(&root)) {
        NABTO_LOG_ERROR(LOG, "Invalid coap response format");
        coap_response_failed(ctx);
    }

    cbor_value_map_find_value(&root, "Status", &status);
    cbor_value_map_find_value(&root, "KeepAlive", &keepAlive);

    if (!cbor_value_is_unsigned_integer(&status)) {
        NABTO_LOG_ERROR(LOG, "Status not an integer");
        coap_response_failed(ctx);
        return;
    }

    uint64_t s;
    cbor_value_get_uint64(&status, &s);

    if (s == ATTACH_STATUS_ATTACHED) {
        handle_device_attached_response(ctx, &root);
        return;
    } else if (s == ATTACH_STATUS_REDIRECT) {
        handle_device_redirect_response(ctx, &root);
        return;
    } else {
        NABTO_LOG_ERROR(LOG, "Status not recognized");
        coap_response_failed(ctx);
        return;
    }
}

np_error_code nc_attacher_register_detach_callback(struct nc_attach_context* ctx, nc_detached_callback cb, void* data)
{
    ctx->detachCb = cb;
    ctx->detachCbData = data;
    return NABTO_EC_OK;
}

np_error_code nc_attacher_detach(struct nc_attach_context* ctx)
{
    switch (ctx->state) {
        case NC_ATTACHER_RESOLVING_DNS:
            ctx->detaching = true;
            break;
        case NC_ATTACHER_CONNECTING_TO_BS:
        case NC_ATTACHER_CONNECTED_TO_BS:
        case NC_ATTACHER_ATTACHED:
            ctx->pl->dtlsC.async_close(ctx->pl, ctx->dtls, ctx->detachCb, ctx->detachCbData);
            break;
    }
    return NABTO_EC_OK;
}
