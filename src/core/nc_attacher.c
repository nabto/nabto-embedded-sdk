
#include "nc_attacher.h"

#include <core/nc_packet.h>
#include <core/nc_coap.h>
#include <platform/np_logging.h>
#include <core/nc_version.h>
#include <core/nc_device.h>
#include <platform/np_event_queue_wrapper.h>
#include <platform/np_allocator.h>

#include <string.h>

#include <nn/string.h>

#include <tinycbor/cbor.h>


#define LOG NABTO_LOG_MODULE_ATTACHER

static const uint32_t ACCESS_DENIED_WAIT_TIME = 3600000; // one hour
static const uint32_t RETRY_WAIT_TIME = 10000; // 10 seconds
static const uint8_t MAX_REDIRECT_FOLLOW = 5;


static const char* defaultRoots =
    "-----BEGIN CERTIFICATE-----\n"
"MIIBsjCCAVigAwIBAgIUIvFEVpiIaq68SzOjGA22IluC4x4wCgYIKoZIzj0EAwIw\n"
"NzELMAkGA1UEBhMCREsxDjAMBgNVBAoMBU5hYnRvMRgwFgYDVQQDDA9OYWJ0byBS\n"
"b290IENBIDEwHhcNMjAxMDAxMDAwMDAwWhcNNDkxMjMxMjM1OTU5WjA3MQswCQYD\n"
"VQQGEwJESzEOMAwGA1UECgwFTmFidG8xGDAWBgNVBAMMD05hYnRvIFJvb3QgQ0Eg\n"
"MTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABP/vVzsNjZzhXLpYRRqHtrBpVpAU\n"
"p6FP2Daja92L05ybDKMYtVXVdD9flnlQG3sSO3heMT0ylJOHVzZtpCrjnYajQjBA\n"
"MB0GA1UdDgQWBBQ01VjuiSzdE1us8ludSEMxSmcbrzAPBgNVHRMBAf8EBTADAQH/\n"
"MA4GA1UdDwEB/wQEAwIBhjAKBggqhkjOPQQDAgNIADBFAiEAlFechrqxujXW7QYR\n"
"sZ7YuikX7ipxkACmrnWQLJ/W5IgCIDVQt/J5XOrbLTpeo3awwOkRxxdO/cSYZC95\n"
"MHEHKTvX\n"
"-----END CERTIFICATE-----\n";

/******************************
 * local function definitions *
 ******************************/
static void do_close(struct nc_attach_context* ctx);
static void reattach(void* data);
static void resolve_close(void* data);

static void handle_state_change(struct nc_attach_context* ctx);
static void handle_dtls_closed(struct nc_attach_context* ctx);
static void handle_dtls_connected(struct nc_attach_context* ctx);
static void reset_dtls_connection(struct nc_attach_context* ctx);
static void handle_keep_alive_data(struct nc_attach_context* ctx, uint8_t* buffer, uint16_t bufferSize);
static void handle_dtls_access_denied(struct nc_attach_context* ctx);
static void handle_dtls_certificate_verification_failed(struct nc_attach_context* ctx);
static np_error_code dtls_packet_sender(uint8_t ch, uint8_t* buffer, uint16_t bufferSize, struct np_completion_event* cb, void* senderData);
static void dtls_data_handler(uint8_t ch, uint64_t seq, uint8_t* buffer, uint16_t bufferSize, void* data);
static void dtls_event_handler(enum np_dtls_event event, void* data);

static void dns_start_resolve(struct nc_attach_context* ctx);
static void dns_resolved_callback(const np_error_code ec, void* data);

static void start_send_initial_packet(struct nc_attach_context* ctx,
                                      uint8_t* buffer, uint16_t bufferSize,
                                      struct np_completion_event* cb);
static void send_initial_packet(struct nc_attach_context* ctx);
static void initial_packet_sent(const np_error_code ec, void* userData);


static void keep_alive_event(void* data);

static void keep_alive_send_req(struct nc_attach_context* ctx);
static void keep_alive_send_response(struct nc_attach_context* ctx, uint8_t* buffer, size_t length);

static void coap_attach_failed(struct nc_attach_context* ctx);

// attach start request
static void send_attach_start_request(struct nc_attach_context* ctx);
static void coap_attach_start_callback(enum nc_attacher_status status, void* data);

// attach end request
static void send_attach_end_request(struct nc_attach_context* ctx);
static void coap_attach_end_handler(np_error_code ec, void* data);

// sct attach request during attach to the basestation.
// this is special because the continuation is sending the attach end request.
void send_attach_sct_request(struct nc_attach_context* ctx);
void send_attach_sct_request_callback(np_error_code ec, void* userData);

// sct request after we are attached.
void send_sct_request(struct nc_attach_context* ctx);
void send_sct_request_callback(np_error_code ec, void* userData);

static void sct_init(struct nc_attach_context* ctx);
static void sct_deinit(struct nc_attach_context* ctx);


/*****************
 * API functions *
 *****************/

np_error_code nc_attacher_init(struct nc_attach_context* ctx, struct np_platform* pl, struct nc_device_context* device, struct nc_coap_client_context* coapClient, nc_attacher_event_listener listener, void* listenerData)
{
    np_error_code ec;

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
    ctx->certValidationDisabled = false;

    struct np_event_queue* eq = &pl->eq;

    ec = np_event_queue_create_event(eq, &reattach, ctx, &ctx->reattachTimer);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_event_queue_create_event(eq, &resolve_close, ctx, &ctx->closeEv);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    sct_init(ctx);

    ec = pl->dtlsC.set_root_certs(pl, defaultRoots);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    // Init keep alive with default values,
    ec = nc_keep_alive_init(&ctx->keepAlive, pl, keep_alive_event, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ec = np_completion_event_init(eq, &ctx->senderCompletionEvent, NULL, NULL);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_completion_event_init(eq, &ctx->resolveCompletionEvent, &dns_resolved_callback, ctx);
    if (ec != NABTO_EC_OK) {
        return ec;
    }
    ec = np_completion_event_init(eq, &ctx->keepAliveSendCtx.ev, &nc_keep_alive_packet_sent, &ctx->keepAlive);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    nc_dns_multi_resolver_init(pl, &ctx->dnsMultiResolver);

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
            nc_udp_dispatch_clear_attacher_context(ctx->udp);
        }
        if (ctx->dtls) {
            ctx->pl->dtlsC.destroy_connection(ctx->dtls);
        }


        if (ctx->request != NULL) {
            nabto_coap_client_request_free(ctx->request);
        }

        sct_deinit(ctx);

        struct np_event_queue* eq = &ctx->pl->eq;
        np_event_queue_destroy_event(eq, ctx->reattachTimer);
        np_event_queue_destroy_event(eq, ctx->closeEv);

        np_completion_event_deinit(&ctx->senderCompletionEvent);
        np_completion_event_deinit(&ctx->resolveCompletionEvent);
        np_completion_event_deinit(&ctx->keepAliveSendCtx.ev);

        nc_dns_multi_resolver_deinit(&ctx->dnsMultiResolver);

        if (ctx->dns != NULL) {
            np_free(ctx->dns);
        }
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
    return ctx->pl->dtlsC.set_keys(ctx->pl, publicKeyL, publicKeySize, privateKeyL, privateKeySize);
}

np_error_code nc_attacher_set_root_certs(struct nc_attach_context* ctx, const char* roots)
{
    if (ctx->moduleState != NC_ATTACHER_MODULE_SETUP) {
        return NABTO_EC_INVALID_STATE;
    }
    return ctx->pl->dtlsC.set_root_certs(ctx->pl, roots);
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
    pl->dtlsC.set_handshake_timeout(ctx->pl, minTimeoutMilliseconds, maxTimeoutMilliseconds);
    return NABTO_EC_OK;
}

static np_error_code update_dns(struct nc_attach_context* ctx , const char* hostname)
{
    if (ctx->dns != NULL) {
        np_free(ctx->dns);
    }
    ctx->dns = nn_strdup(hostname, np_allocator_get());
    if (ctx->dns == NULL) {
        return NABTO_EC_OUT_OF_MEMORY;
    }
    return NABTO_EC_OK;
}

np_error_code nc_attacher_start(struct nc_attach_context* ctx, const char* hostname, uint16_t serverPort, struct nc_udp_dispatch_context* udp)
{
    if (ctx->moduleState != NC_ATTACHER_MODULE_SETUP) {
        return NABTO_EC_INVALID_STATE;
    }

    np_error_code ec = update_dns(ctx,hostname);
    if (ec != NABTO_EC_OK) {
        return ec;
    }

    ctx->udp = udp;
    ctx->state = NC_ATTACHER_STATE_DNS;
    ctx->moduleState = NC_ATTACHER_MODULE_RUNNING;
    ctx->hostname = hostname;
    ctx->defaultPort = serverPort;
    ctx->currentPort = serverPort;

    nc_udp_dispatch_set_attach_context(ctx->udp, ctx);
    handle_state_change(ctx);
    return NABTO_EC_OK;
}

np_error_code nc_attacher_restart(struct nc_attach_context* ctx)
{
    if (ctx->moduleState != NC_ATTACHER_MODULE_CLOSED) {
        return NABTO_EC_INVALID_STATE;
    }

    ctx->moduleState = NC_ATTACHER_MODULE_RUNNING;
    // If state CLOSED we reattach
    if (ctx->state ==  NC_ATTACHER_STATE_CLOSED) {
        reattach(ctx);
    }
    // else if closing is in progress, setting the moduleState above will cause the module to reattach automatically
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
    nc_keep_alive_stop(&ctx->keepAlive);

    do_close(ctx);
    return NABTO_EC_OK;
}

np_error_code nc_attacher_add_server_connect_token(struct nc_attach_context* ctx, const char* token)
{
    ctx->sctContext.version++;
    if (!nn_string_set_insert(&ctx->sctContext.scts, token))
    {
        return NABTO_EC_OUT_OF_MEMORY;
    }

    if (ctx->state == NC_ATTACHER_STATE_ATTACHED) {
        send_sct_request(ctx);
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
        np_event_queue_post(&ctx->pl->eq, ctx->closeEv);
        return;
    }
    ctx->moduleState = NC_ATTACHER_MODULE_CLOSED;
    switch(ctx->state) {
        case NC_ATTACHER_STATE_RETRY_WAIT:
        case NC_ATTACHER_STATE_ACCESS_DENIED_WAIT:
            np_event_queue_cancel_event(&ctx->pl->eq, ctx->reattachTimer);
            ctx->state = NC_ATTACHER_STATE_CLOSED;
            handle_state_change(ctx);
            break;
        case NC_ATTACHER_STATE_CLOSED:
            np_event_queue_post(&ctx->pl->eq, ctx->closeEv);
            break;
        case NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST:
        case NC_ATTACHER_STATE_ATTACHED:
            ctx->pl->dtlsC.async_close(ctx->dtls);
            break;
        case NC_ATTACHER_STATE_DNS:
            NABTO_LOG_INFO(LOG, "Resolving DNS must finish before close can complete. This can take a while");

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
    np_event_queue_cancel_event(&ctx->pl->eq, ctx->reattachTimer);
    if (ctx->closedCb) {
        nc_attacher_closed_callback cb = ctx->closedCb;
        ctx->closedCb = NULL;
        cb(ctx->closedCbData);
    }
}

char* state_to_text(enum nc_attacher_attach_state state) {
    switch(state) {
    case NC_ATTACHER_STATE_DNS:
        return "NC_ATTACHER_STATE_DNS";
    case NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST:
        return "NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST";
    case NC_ATTACHER_STATE_RETRY_WAIT:
        return "NC_ATTACHER_STATE_RETRY_WAIT";
    case NC_ATTACHER_STATE_ACCESS_DENIED_WAIT:
        return "NC_ATTACHER_STATE_ACCESS_DENIED_WAIT";
    case NC_ATTACHER_STATE_REDIRECT:
        return "NC_ATTACHER_STATE_REDIRECT";
    case NC_ATTACHER_STATE_ATTACHED:
        return "NC_ATTACHER_STATE_ATTACHED";
    case NC_ATTACHER_STATE_CLOSED:
        return "NC_ATTACHER_STATE_CLOSED";
    }
    return "UNKNOWN STATE - ERROR";
}


void handle_state_change(struct nc_attach_context* ctx)
{
    NABTO_LOG_TRACE(LOG, "State change to: %s", state_to_text(ctx->state));
    switch(ctx->state) {
        case NC_ATTACHER_STATE_DNS:
            dns_start_resolve(ctx);
            break;
        case NC_ATTACHER_STATE_CLOSED:
            np_event_queue_post(&ctx->pl->eq, ctx->closeEv);
            break;
        case NC_ATTACHER_STATE_REDIRECT:
            break;
        case NC_ATTACHER_STATE_RETRY_WAIT:
            np_event_queue_post_timed_event(&ctx->pl->eq, ctx->reattachTimer, ctx->retryWaitTime);
            break;
        case NC_ATTACHER_STATE_ACCESS_DENIED_WAIT:
            np_event_queue_post_timed_event(&ctx->pl->eq, ctx->reattachTimer, ctx->accessDeniedWaitTime);
            break;
        case NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST:
        {
            np_error_code ec = ctx->pl->dtlsC.create_attach_connection(
                ctx->pl, &ctx->dtls, ctx->hostname, ctx->certValidationDisabled, &dtls_packet_sender,
                &dtls_data_handler, &dtls_event_handler, ctx);
                if (ec != NABTO_EC_OK) {
                    NABTO_LOG_ERROR(LOG, "Dtls connection creation failed");
                    ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
                    handle_state_change(ctx);
                    return;
                }
            ctx->pl->dtlsC.connect(ctx->dtls);
        }
            break;
        case NC_ATTACHER_STATE_ATTACHED:
            // Nothing to do when attached

            break;
    }
    if (ctx->stateListener != NULL) {
        ctx->stateListener(ctx->state, ctx->stateListenerData);
    }
}

void dns_start_resolve(struct nc_attach_context* ctx)
{
    NABTO_LOG_TRACE(LOG, "Resolving Attach Server DNS name %s", ctx->dns);
    nc_dns_multi_resolver_resolve(&ctx->dnsMultiResolver, ctx->dns, ctx->resolvedIps, NC_ATTACHER_MAX_IPS, &ctx->resolvedIpsSize, &ctx->resolveCompletionEvent);
}

void dns_resolved_callback(const np_error_code ec, void* data)
{
    struct nc_attach_context* ctx = data;
    if (ctx->moduleState == NC_ATTACHER_MODULE_CLOSED) {
        ctx->state = NC_ATTACHER_STATE_CLOSED;
        handle_state_change(ctx);
        return;
    }

    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to resolve attach dispatcher host: %s (%u)%s", ctx->dns, ec, np_error_code_to_string(ec));
        // No DTLS to close so we go directly to RETRY WAIT
        ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
        handle_state_change(ctx);
        return;
    }

    ctx->initialPacket.endpointsSize = 0;
    ctx->initialPacket.endpointsIndex = 0;

    size_t ipsSize = ctx->resolvedIpsSize;

    for (size_t i = 0; i < ipsSize; i++) {
        if (ctx->initialPacket.endpointsIndex < NC_ATTACHER_MAX_ENDPOINTS) {
            ctx->initialPacket.endpoints[ctx->initialPacket.endpointsSize].ip = ctx->resolvedIps[i];
            ctx->initialPacket.endpoints[ctx->initialPacket.endpointsSize].port = ctx->currentPort;
            ctx->initialPacket.endpointsSize++;
        }
    }

    ctx->hasActiveEp = false;

    ctx->state = NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST;
    handle_state_change(ctx);
}

void reattach(void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    if (ctx->moduleState == NC_ATTACHER_MODULE_CLOSED) {
        ctx->state = NC_ATTACHER_STATE_CLOSED;
    } else {
        np_error_code ec = update_dns(ctx, ctx->hostname);
        if (ec != NABTO_EC_OK) {
            NABTO_LOG_ERROR(LOG, "Failed to update the dns address");
            ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
        } else {
            ctx->currentPort = ctx->defaultPort;
            ctx->state = NC_ATTACHER_STATE_DNS;
            ctx->redirectAttempts = 0;
        }
    }
    handle_state_change(ctx);
}

void dtls_event_handler(enum np_dtls_event event, void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    if (ctx->moduleState == NC_ATTACHER_MODULE_CLOSED) {
        if (event == NP_DTLS_EVENT_HANDSHAKE_COMPLETE) {
            ctx->pl->dtlsC.async_close(ctx->dtls);
        } else {
            reset_dtls_connection(ctx);
            ctx->state = NC_ATTACHER_STATE_CLOSED;
            handle_state_change(ctx);
        }
        return;
    }

    if (event == NP_DTLS_EVENT_HANDSHAKE_COMPLETE) {
        handle_dtls_connected(ctx);
    } else if (event == NP_DTLS_EVENT_CLOSED) {
        handle_dtls_closed(ctx);
    } else if (event == NP_DTLS_EVENT_ACCESS_DENIED) {
        handle_dtls_access_denied(ctx);
    } else if (event == NP_DTLS_EVENT_CERTIFICATE_VERIFICATION_FAILED) {
        handle_dtls_certificate_verification_failed(ctx);
    }
}

/**
 * Method which resets the associated state with a dtls connection whenever the
 * connection is closed expectedly or by an unexpected error.
 */
void reset_dtls_connection(struct nc_attach_context* ctx)
{
    nc_keep_alive_reset(&ctx->keepAlive);
    nabto_coap_client_remove_connection(nc_coap_client_get_client(ctx->coapClient), ctx->dtls);
    if (ctx->dtls) {
        ctx->pl->dtlsC.destroy_connection(ctx->dtls);
        ctx->dtls = NULL;
    }
    if (ctx->request != NULL) {
        nabto_coap_client_request_free(ctx->request);
        ctx->request = NULL;
    }
    if (ctx->state == NC_ATTACHER_STATE_ATTACHED) {
        if (ctx->listener) {
            ctx->listener(NC_DEVICE_EVENT_DETACHED, ctx->listenerData);
        }
        NABTO_LOG_INFO(LOG, "Device detached from basestation");
    }
}

void handle_dtls_closed(struct nc_attach_context* ctx)
{
    reset_dtls_connection(ctx);
    // dtls_event_handler() only calls this after moduleState has been checked so we dont need to here
    switch(ctx->state) {
        case NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST:
            // DTLS connect failed and dtls was closed, wait to retry
            // Coap request payload could not be set maybe OOM
            // DTLS was closed while waiting for coap response, most likely closed by peer, wait to retry
            ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
            handle_state_change(ctx);
            break;
        case NC_ATTACHER_STATE_ATTACHED:
            // DTLS was closed while attached, closed by peer or keep alive timeout. Try reattach
            ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
            handle_state_change(ctx);
            break;
        case NC_ATTACHER_STATE_REDIRECT:
            if (ctx->redirectAttempts >= MAX_REDIRECT_FOLLOW) {
                ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
            } else {
                // DTLS closed since BS redirected us, resolve new BS.
                ctx->state = NC_ATTACHER_STATE_DNS;
            }
            handle_state_change(ctx);
            break;
        case NC_ATTACHER_STATE_ACCESS_DENIED_WAIT:

            // we have reset the dtls context
            break;
        default:
            // states DNS, RETRY_WAIT, CLOSED does not have a DTLS connection which can be closed
            // If this impossible error happens, simply try reattach
            ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
            handle_state_change(ctx);
    }
}

void handle_dtls_connected(struct nc_attach_context* ctx)
{
    send_attach_start_request(ctx);
}

void handle_dtls_access_denied(struct nc_attach_context* ctx)
{
    NABTO_LOG_TRACE(LOG, "Received access denied from state: %u", ctx->state);
    reset_dtls_connection(ctx);

    ctx->state = NC_ATTACHER_STATE_ACCESS_DENIED_WAIT;
    handle_state_change(ctx);
}

void handle_dtls_certificate_verification_failed(struct nc_attach_context* ctx)
{
    NABTO_LOG_TRACE(LOG, "Received certificate verification failed from state: %u", ctx->state);
    reset_dtls_connection(ctx);

    if (ctx->listener) {
        ctx->listener(NC_DEVICE_EVENT_CERTIFICATE_VALIDATION_FAILED, ctx->listenerData);
    }

    ctx->state = NC_ATTACHER_STATE_RETRY_WAIT;
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

    if (ctx->moduleState == NC_ATTACHER_MODULE_CLOSED) {
        coap_attach_failed(ctx);
        return;
    }

    if (status == NC_ATTACHER_STATUS_ATTACHED) {
        send_attach_sct_request(ctx);
        return;
    } else if (status == NC_ATTACHER_STATUS_REDIRECT) {
        ctx->state = NC_ATTACHER_STATE_REDIRECT;
        ctx->redirectAttempts++;
        ctx->pl->dtlsC.async_close(ctx->dtls);
        return;
    } else if (status == NC_ATTACHER_STATUS_UNKNOWN_FINGERPRINT && ctx->listener) {
        ctx->listener(NC_DEVICE_EVENT_UNKNOWN_FINGERPRINT, ctx->listenerData);
    } else if (status == NC_ATTACHER_STATUS_WRONG_PRODUCT_ID && ctx->listener) {
        ctx->listener(NC_DEVICE_EVENT_WRONG_PRODUCT_ID, ctx->listenerData);
    } else if (status == NC_ATTACHER_STATUS_WRONG_DEVICE_ID && ctx->listener) {
        ctx->listener(NC_DEVICE_EVENT_WRONG_DEVICE_ID, ctx->listenerData);
    }
    coap_attach_failed(ctx);
}

void send_attach_sct_request(struct nc_attach_context* ctx)
{
    ctx->sctContext.synchronizedVersion = 0;
    np_error_code ec = nc_attacher_sct_upload(ctx, &send_attach_sct_request_callback, ctx);
    if (ec == NABTO_EC_NO_OPERATION) {
        send_attach_end_request(ctx);
    } else if (ec == NABTO_EC_OPERATION_STARTED) {
        // wait for callback
    } else {
        // an error occured fail the attach.
        coap_attach_failed(ctx);
    }
}

void send_attach_sct_request_callback(np_error_code ec, void* userData)
{
    struct nc_attach_context* ctx = userData;

    if (ctx->moduleState == NC_ATTACHER_MODULE_CLOSED) {
        coap_attach_failed(ctx);
        return;
    }

    if (ec == NABTO_EC_OK) {
        send_attach_end_request(ctx);
    } else {
        coap_attach_failed(ctx);
    }
}

void send_sct_request(struct nc_attach_context* ctx)
{
    np_error_code ec = nc_attacher_sct_upload(ctx, &send_sct_request_callback, ctx);
    if (ec == NABTO_EC_NO_OPERATION) {
        return;
    } else if (ec == NABTO_EC_OPERATION_STARTED) {
        // wait for callback
    } else {
        // an error occured, do not care.
    }
}

void send_sct_request_callback(np_error_code ec, void* userData)
{
    struct nc_attach_context* ctx = userData;

    if (ec == NABTO_EC_OK) {
        // check if there is more scts to be sent
        send_sct_request(ctx);
    }
}

void send_attach_end_request(struct nc_attach_context* ctx)
{
    np_error_code ec = nc_attacher_attach_end_request(ctx, coap_attach_end_handler, ctx);
    if (ec != NABTO_EC_OPERATION_STARTED) {
        coap_attach_failed(ctx);
    }
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
    nc_keep_alive_wait(&ctx->keepAlive);
    ctx->state = NC_ATTACHER_STATE_ATTACHED;
    handle_state_change(ctx);
    if (ctx->listener) {
        NABTO_LOG_INFO(LOG, "Device attached to basestation");
        ctx->listener(NC_DEVICE_EVENT_ATTACHED, ctx->listenerData);
    }

    // if we have added scts in the meantime
    send_sct_request(ctx);
}

void coap_attach_failed(struct nc_attach_context* ctx)
{
    ctx->pl->dtlsC.async_close(ctx->dtls);
}

void nc_attacher_handle_dtls_packet(struct nc_attach_context* ctx, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize)
{
    struct np_platform* pl = ctx->pl;
    if (!ctx->dtls) {
        return;
    }
    // handle_packet can currently not fail, so checking its return
    // value is futile. It will trigger responses to be sent, so we
    // must set hasActiveEp before calling. if handle_packet becomes
    // able to fail, hasActiveEp must either be reset after
    // handle_packet, or the connection will be allowed to die and we
    // will retry.
    if (!ctx->hasActiveEp) {
        ctx->activeEp = *ep;
        ctx->hasActiveEp = true;
    }
    pl->dtlsC.handle_packet(ctx->dtls, 0, buffer, (uint16_t)bufferSize);
}

np_error_code dtls_packet_sender(uint8_t ch, uint8_t* buffer, uint16_t bufferSize,
                                 struct np_completion_event* cb,
                                 void* senderData)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)senderData;
    if (!ctx->hasActiveEp) {
        // We have yet to find suitable endpoint
        start_send_initial_packet(ctx, buffer, bufferSize, cb);
        return NABTO_EC_OK;
    } else {
        nc_udp_dispatch_async_send_to(ctx->udp, &ctx->activeEp,
                                      buffer, bufferSize,
                                      cb);
        return NABTO_EC_OK;
    }
}

void start_send_initial_packet(struct nc_attach_context* ctx,
                               uint8_t* buffer, uint16_t bufferSize,
                               struct np_completion_event* cb)
{
    // send the packet to all the endpoints
    ctx->initialPacket.cb = cb;
    ctx->initialPacket.buffer = buffer;
    ctx->initialPacket.bufferSize = bufferSize;
    ctx->initialPacket.endpointsIndex = 0;
    send_initial_packet(ctx);
}

void send_initial_packet(struct nc_attach_context* ctx)
{
    if (ctx->initialPacket.endpointsIndex >= ctx->initialPacket.endpointsSize) {
        np_completion_event_resolve(ctx->initialPacket.cb, NABTO_EC_OK);
        return;
    }
    np_completion_event_reinit(&ctx->senderCompletionEvent, &initial_packet_sent, ctx);
    nc_udp_dispatch_async_send_to(ctx->udp, &ctx->initialPacket.endpoints[ctx->initialPacket.endpointsIndex],
                                  ctx->initialPacket.buffer, (uint16_t)ctx->initialPacket.bufferSize,
                                  &ctx->senderCompletionEvent);
    ctx->initialPacket.endpointsIndex++;
}

void initial_packet_sent(const np_error_code ec, void* userData)
{
    (void)ec;
    struct nc_attach_context* ctx = userData;
    // do not care about send errors
    send_initial_packet(ctx);
}

void dtls_data_handler(uint8_t ch, uint64_t seq, uint8_t* buffer, uint16_t bufferSize, void* data)
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

void keep_alive_event(void* data)
{
    struct nc_attach_context* ctx = (struct nc_attach_context*)data;
    struct np_platform* pl = ctx->pl;

    uint32_t recvCount;
    uint32_t sentCount;

    pl->dtlsC.get_packet_count(ctx->dtls, &recvCount, &sentCount);
    enum nc_keep_alive_action action = nc_keep_alive_should_send(&ctx->keepAlive, recvCount, sentCount);
    switch(action) {
        case DO_NOTHING:
            nc_keep_alive_wait(&ctx->keepAlive);
            break;
        case SEND_KA:
            keep_alive_send_req(ctx);
            nc_keep_alive_wait(&ctx->keepAlive);
            break;
        case KA_TIMEOUT:
            ctx->pl->dtlsC.async_close(ctx->dtls);
            break;
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
    struct np_dtls_send_context* sendCtx = &ctx->keepAliveSendCtx;

    nc_keep_alive_create_request(&ctx->keepAlive, &sendCtx->buffer, (size_t*)&sendCtx->bufferSize);

    pl->dtlsC.async_send_data(ctx->dtls, sendCtx);
}

void keep_alive_send_response(struct nc_attach_context* ctx, uint8_t* buffer, size_t length)
{
    struct np_platform* pl = ctx->pl;
    struct np_dtls_send_context* sendCtx = &ctx->keepAliveSendCtx;
    if(nc_keep_alive_handle_request(&ctx->keepAlive, buffer, length, &sendCtx->buffer, (size_t*)&sendCtx->bufferSize)) {
        pl->dtlsC.async_send_data(ctx->dtls, sendCtx);
    }
}

void sct_init(struct nc_attach_context* ctx)
{
    struct nc_attacher_sct_context* sctCtx = &ctx->sctContext;
    nn_string_set_init(&sctCtx->scts, np_allocator_get());
    sctCtx->version = 0;
    sctCtx->synchronizedVersion = 0;
    sctCtx->uploadingVersion = 0;
    sctCtx->callback = NULL;
    sctCtx->callbackUserData = NULL;
}

void sct_deinit(struct nc_attach_context* ctx)
{
    nn_string_set_deinit(&ctx->sctContext.scts);
}

void nc_attacher_disable_certificate_validation(struct nc_attach_context* ctx)
{
    ctx->certValidationDisabled = true;
}
