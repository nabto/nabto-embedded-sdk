#ifndef NC_ATTACHER_H
#define NC_ATTACHER_H

#include <platform/np_platform.h>
#include <core/nc_udp_dispatch.h>
#include <core/nc_coap_client.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NABTO_MAX_BASESTATION_EPS 2

enum nc_device_event {
    NC_DEVICE_EVENT_ATTACHED,
    NC_DEVICE_EVENT_DETACHED,
    NC_DEVICE_EVENT_FAILURE
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
    np_dtls_cli_context* dtls;

    nc_attacher_state_listener stateListener;
    void* stateListenerData;

    // Internal state
    enum nc_attacher_attach_state state;
    enum nc_attacher_module_state moduleState;

    uint32_t sessionId;
    struct nc_attach_endpoint_context v4BsEps[NABTO_MAX_BASESTATION_EPS];
    struct nc_attach_endpoint_context v6BsEps[NABTO_MAX_BASESTATION_EPS];
    struct nc_attach_endpoint_context* activeEp;
    uint8_t bsEpsTried;

    uint16_t currentPort;
    char dns[256];
    uint8_t dnsLen;

    uint8_t redirectAttempts;
    struct np_timed_event reattachTimer;
    struct np_event closeEv;

    struct nabto_coap_client_request* request;

    char stunHost[256];
    uint16_t stunPort;

    // Keep alive
    struct nc_keep_alive_context keepAlive;
    struct np_dtls_cli_send_context keepAliveSendCtx;

    // external callbacks
    nc_attacher_closed_callback closedCb;
    void* closedCbData;

    np_dtls_cli_send_callback senderCb;
    void* senderCbData;

    // configurable for testing purposes.
    uint32_t retryWaitTime;
    uint32_t accessDeniedWaitTime;
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
np_error_code nc_attacher_start(struct nc_attach_context* ctx,
                                const char* hostname,
                                uint16_t serverPort,
                                struct nc_udp_dispatch_context* udp);

// Close the module nicely
np_error_code nc_attacher_async_close(struct nc_attach_context* ctx,
                                      nc_attacher_closed_callback callback,
                                      void* userData);

// Stop the module forcefully
np_error_code nc_attacher_stop(struct nc_attach_context* ctx);

#ifdef __cplusplus
} // extern c
#endif

#endif //NC_ATTACHER_H
