#ifndef NC_ATTACHER_H
#define NC_ATTACHER_H

#include <core/nc_coap_client.h>
#include <core/nc_device_defines.h>
#include <core/nc_dns_multi_resolver.h>
#include <core/nc_udp_dispatch.h>
#include <platform/np_completion_event.h>
#include <platform/np_platform.h>

#include <nn/string_set.h>


#ifdef __cplusplus
extern "C" {
#endif

#define NABTO_MAX_BASESTATION_EPS 2

struct nabto_coap_client_request;

typedef void (*nc_attacher_fcm_send_callback)(const np_error_code ec, void* userData);

struct nc_attacher_fcm_request {
    char* projectId;
    char* payload;
};

struct nc_attacher_fcm_response {
    char* body;
    uint16_t statusCode;
};

struct nc_attacher_fcm_send_context {
    struct nc_attacher_fcm_request fcmRequest;
    struct nc_attacher_fcm_response fcmResponse;

    const char* pathSegments[3];
    struct nabto_coap_client_request* coapRequest;
    nc_attacher_fcm_send_callback cb;
    void* cbData;
};

typedef void (*nc_attacher_service_invoke_callback)(const np_error_code ec, void* userData);

struct nc_attacher_service_invoke_request {
    char* serviceId;
    uint8_t* message;
    size_t messageLength;
};

enum nc_attacher_service_invoke_message_format {
    NC_SERVICE_INVOKE_MESSAGE_FORMAT_BINARY = 0,
    NC_SERVICE_INVOKE_MESSAGE_FORMAT_NONE = 1,
    NC_SERVICE_INVOKE_MESSAGE_FORMAT_TEXT = 2
    };

struct nc_attacher_service_invoke_response {
    uint8_t* message;
    size_t messageLength;
    enum nc_attacher_service_invoke_message_format messageFormat;
    uint16_t statusCode;
};

struct nc_attacher_service_invoke_context {
    struct nc_attacher_service_invoke_request serviceInvokeRequest;
    struct nc_attacher_service_invoke_response serviceInvokeResponse;

    struct nabto_coap_client_request* coapRequest;
    nc_attacher_service_invoke_callback cb;
    void* cbData;
};

typedef void (*nc_attacher_request_ice_servers_callback)(const np_error_code ec, void* userData);

struct nc_attacher_ice_server {
    char* username;
    char* credential;
    struct nn_vector urls;
};

struct nc_attacher_request_ice_servers_context {
    struct nabto_coap_client_request* coapRequest;
    struct nc_attach_context* attacher;
    struct nn_vector iceServers;
    nc_attacher_request_ice_servers_callback cb;
    void* cbData;
};

typedef void (*nc_attacher_closed_callback)(void* data);
typedef void (*nc_attacher_event_listener)(enum nc_device_event event, void* data);

enum nc_attacher_attach_state {
    NC_ATTACHER_STATE_DNS,
    NC_ATTACHER_STATE_DTLS_ATTACH_REQUEST,
    NC_ATTACHER_STATE_RETRY_WAIT,
    NC_ATTACHER_STATE_ACCESS_DENIED_WAIT,
    NC_ATTACHER_STATE_REDIRECT,
    NC_ATTACHER_STATE_ATTACHED,
    NC_ATTACHER_STATE_CLOSED
};

typedef void (*nc_attacher_state_listener)(enum nc_attacher_attach_state state, void* data);

enum nc_attacher_module_state {
    NC_ATTACHER_MODULE_SETUP,
    NC_ATTACHER_MODULE_RUNNING,
    NC_ATTACHER_MODULE_CLOSED
};

struct nc_attach_endpoint_context {
    struct nc_attach_context* ctx;
    struct np_udp_endpoint ep;
    struct np_completion_event sendCompletionEvent;
};

enum nc_attacher_status {
    NC_ATTACHER_STATUS_ATTACHED,
    NC_ATTACHER_STATUS_REDIRECT,
    NC_ATTACHER_STATUS_ERROR,
    NC_ATTACHER_STATUS_UNKNOWN_FINGERPRINT,
    NC_ATTACHER_STATUS_WRONG_PRODUCT_ID,
    NC_ATTACHER_STATUS_WRONG_DEVICE_ID
};

typedef void (*nc_attacher_attach_start_callback)(enum nc_attacher_status status, void* userData);
typedef void (*nc_attacher_attach_end_callback)(np_error_code ec, void* userData);

typedef void (*nc_attacher_sct_callback)(np_error_code ec, void* userData);

struct nc_attacher_sct_context {
    struct nn_string_set scts;
    uint64_t version;
    uint64_t synchronizedVersion;
    uint64_t uploadingVersion;
    nc_attacher_sct_callback callback;
    void* callbackUserData;
};

#define NC_ATTACHER_MAX_ENDPOINTS 4
#define NC_ATTACHER_MAX_IPS 4

struct nc_attacher_initial_packet_send
{
    uint8_t* buffer;
    size_t bufferSize;
    struct np_completion_event* cb;
    size_t endpointsIndex;
    size_t endpointsSize;

    struct np_udp_endpoint endpoints[NC_ATTACHER_MAX_ENDPOINTS];
};

struct nc_attach_context {
    // External references
    struct np_platform* pl;
    struct nc_device_context* device;

    const char* appName;
    const char* appVersion;
    const char* productId;
    const char* deviceId;
    const char* hostname;
    uint16_t defaultPort;

    nc_attacher_event_listener listener;
    void* listenerData;
    struct nc_coap_client_context* coapClient;
    struct nc_udp_dispatch_context* udp;
    struct np_dtls_cli_connection* dtls;

    nc_attacher_state_listener stateListener;
    void* stateListenerData;

    // Internal state
    enum nc_attacher_attach_state state;
    enum nc_attacher_module_state moduleState;

    uint32_t sessionId;
    struct nc_attacher_initial_packet_send initialPacket;
    struct np_udp_endpoint activeEp;
    bool hasActiveEp;
    uint8_t bsEpsTried;

    bool certValidationDisabled;

    uint16_t currentPort;
    char* dns;

    struct nc_dns_multi_resolver_context dnsMultiResolver;
    struct np_ip_address resolvedIps[NC_ATTACHER_MAX_IPS];
    size_t resolvedIpsSize;
    struct np_completion_event resolveCompletionEvent;

    uint8_t redirectAttempts;
    struct np_event* reattachTimer;
    struct np_event* closeEv;
    struct np_event* deferredHandleStateChange;

    nc_attacher_attach_start_callback startCallback;
    void* startCallbackUserData;

    nc_attacher_attach_end_callback endCallback;
    void* endCallbackUserData;


    struct nabto_coap_client_request* request;

    // Keep alive
    struct nc_keep_alive_context keepAlive;
    struct np_dtls_send_context keepAliveSendCtx;

    // external callbacks
    nc_attacher_closed_callback closedCb;
    void* closedCbData;

    struct np_completion_event senderCompletionEvent;

    // configurable for testing purposes.
    uint32_t retryWaitTime;
    uint32_t accessDeniedWaitTime;

    struct nc_attacher_sct_context sctContext;
};

// Init attacher module, always first function to be called
np_error_code nc_attacher_init(struct nc_attach_context* ctx, struct np_platform* pl,
                               struct nc_device_context* device, struct nc_coap_client_context* coapClient,
                               nc_attacher_event_listener listener, void* listenerData);

// deinit attacher module, always last function to be called, called after stop
void nc_attacher_deinit(struct nc_attach_context* ctx);

// Set callback for every state change in the module. This is meant for testing purposes only!
void nc_attacher_set_state_listener(struct nc_attach_context* ctx, nc_attacher_state_listener cb, void* data);

// set keys before start
np_error_code nc_attacher_set_keys(struct nc_attach_context* ctx,
                                   const unsigned char* publicKeyL, size_t publicKeySize,
                                   const unsigned char* privateKeyL, size_t privateKeySize);

np_error_code nc_attacher_set_root_certs(struct nc_attach_context* ctx, const char* roots);

// set app info before start
np_error_code nc_attacher_set_app_info(struct nc_attach_context* ctx,
                                       const char* appName,
                                       const char* appVersion);

np_error_code nc_attacher_set_device_info(struct nc_attach_context* ctx,
                                          const char* productId,
                                          const char* deviceId);

np_error_code nc_attacher_set_handshake_timeout(struct nc_attach_context* ctx,
                                                uint32_t minTimeoutMilliseconds, uint32_t maxTimeoutMilliseconds);

// Start the attach module
// Cannot be called twice
np_error_code nc_attacher_start(struct nc_attach_context* ctx,
                                const char* hostname,
                                uint16_t serverPort,
                                struct nc_udp_dispatch_context* udp);

// restart the attach module after having been closed
np_error_code nc_attacher_restart(struct nc_attach_context* ctx);

// Close the module nicely
np_error_code nc_attacher_async_close(struct nc_attach_context* ctx,
                                      nc_attacher_closed_callback callback,
                                      void* userData);

// Stop the module forcefully
np_error_code nc_attacher_stop(struct nc_attach_context* ctx);

np_error_code nc_attacher_add_server_connect_token(struct nc_attach_context* ctx, const char* token);

np_error_code nc_attacher_is_server_connect_tokens_synchronized(struct nc_attach_context* ctx);

np_error_code nc_attacher_sct_upload(struct nc_attach_context* attacher, nc_attacher_sct_callback cb, void* userData);

/**
 * @return NABTO_EC_OPERATION_STARTED if the attach start request is started.
 */
np_error_code nc_attacher_attach_start_request(struct nc_attach_context* attacher, nc_attacher_attach_start_callback cb, void* userData);

/**
 * @return NABTO_EC_OPERATION_STARTED if the attach end request is started.
 */
np_error_code nc_attacher_attach_end_request(struct nc_attach_context* attacher, nc_attacher_attach_end_callback cb, void* userData);

void nc_attacher_handle_dtls_packet(struct nc_attach_context* ctx, struct np_udp_endpoint* ep, uint8_t* buffer, size_t bufferSize);


np_error_code nc_attacher_fcm_send(struct nc_attach_context* attacher, struct nc_attacher_fcm_send_context* fcmSend, nc_attacher_fcm_send_callback cb, void* userData);

void nc_attacher_fcm_send_stop(struct nc_attacher_fcm_send_context* fcmSend);

np_error_code nc_attacher_service_invoke_execute(struct nc_attach_context* attacher, struct nc_attacher_service_invoke_context* serviceInvoke, nc_attacher_service_invoke_callback cb, void* userData);

void nc_attacher_service_invoke_stop(struct nc_attacher_service_invoke_context* serviceInvoke);


void nc_attacher_ice_servers_ctx_init(struct nc_attacher_request_ice_servers_context* ctx, struct nc_attach_context* attacher);

void nc_attacher_ice_servers_ctx_deinit(struct nc_attacher_request_ice_servers_context* ctx);

np_error_code nc_attacher_request_ice_servers(struct nc_attacher_request_ice_servers_context* ctx, const char* identifier, nc_attacher_request_ice_servers_callback cb, void* userData);

void nc_attacher_disable_certificate_validation(struct nc_attach_context* attacher);

#ifdef __cplusplus
} // extern c
#endif

#endif //NC_ATTACHER_H
