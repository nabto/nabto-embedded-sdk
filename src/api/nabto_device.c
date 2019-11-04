#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include <api/nabto_device_defines.h>
#include <api/nabto_device_stream.h>
#include <api/nabto_device_coap.h>
#include <api/nabto_device_future.h>
#include <api/nabto_device_event_handler.h>
#include <api/nabto_api_future_queue.h>
#include <api/nabto_platform.h>
#include <api/nabto_device_coap.h>
#include <platform/np_error_code.h>

#include <platform/np_logging.h>
#include <platform/np_error_code.h>
#include <core/nc_version.h>
#include <core/nc_client_connection.h>

#include <modules/logging/api/nm_api_logging.h>
#include <modules/dtls/nm_dtls_util.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

// TODO: Take though api or something
const char* stunHost = "stun.nabto.net";

void* nabto_device_network_thread(void* data);
void* nabto_device_core_thread(void* data);
void nabto_device_init_platform(struct np_platform* pl);
void nabto_device_free_threads(struct nabto_device_context* dev);
NabtoDeviceError  nabto_device_create_crt_from_private_key(struct nabto_device_context* dev);

const char* nabto_device_version()
{
    return NABTO_VERSION;
}

void notify_event_queue_post(void* data)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)data;
    nabto_device_threads_cond_signal(dev->eventCond);
}

/**
 * Allocate new device
 */
NabtoDevice* NABTO_DEVICE_API nabto_device_new()
{
    struct nabto_device_context* dev = (struct nabto_device_context*)malloc(sizeof(struct nabto_device_context));
    if (dev == NULL) {
        return NULL;
    }
    memset(dev, 0, sizeof(struct nabto_device_context));

    nabto_device_init_platform(&dev->pl);
    nabto_device_init_platform_modules(&dev->pl);
    dev->closing = false;
    dev->eventMutex = nabto_device_threads_create_mutex();
    if (dev->eventMutex == NULL) {
        // todo make better cleanup
        NABTO_LOG_ERROR(LOG, "mutex init has failed");
        nabto_device_platform_close(&dev->pl);
        free(dev);
        return NULL;
    }
    dev->eventCond = nabto_device_threads_create_condition();
    if (dev->eventCond == NULL) {
        NABTO_LOG_ERROR(LOG, "condition init has failed");
        nabto_device_free_threads(dev);
        nabto_device_platform_close(&dev->pl);
        free(dev);
        return NULL;
    }
    dev->futureQueueMutex = nabto_device_threads_create_mutex();
    if (dev->futureQueueMutex == NULL) {
        NABTO_LOG_ERROR(LOG, "future queue mutex init has failed");
        nabto_device_free_threads(dev);
        nabto_device_platform_close(&dev->pl);
        free(dev);
        return NULL;
    }

    dev->coreThread = nabto_device_threads_create_thread();
    dev->networkThread = nabto_device_threads_create_thread();
    if (dev->coreThread == NULL || dev->networkThread == NULL) {
        nabto_device_free_threads(dev);
        nabto_device_platform_close(&dev->pl);
        free(dev);
        return NULL;
    }

    np_event_queue_init(&dev->pl, &notify_event_queue_post, dev);

    if (nabto_device_threads_run(dev->coreThread, nabto_device_core_thread, dev) != 0) {
        NABTO_LOG_ERROR(LOG, "Failed to run core thread");
        nabto_device_free_threads(dev);
        nabto_device_platform_close(&dev->pl);
        free(dev);
        return NULL;
    }
    if (nabto_device_threads_run(dev->networkThread, nabto_device_network_thread, dev) != 0) {
        NABTO_LOG_ERROR(LOG, "Failed to run network thread");
        dev->closing = true;
        nabto_device_threads_cond_signal(dev->eventCond);
        nabto_device_threads_join(dev->coreThread);
        nabto_device_free_threads(dev);
        nabto_device_platform_close(&dev->pl);
        free(dev);
        return NULL;
    }
    np_error_code ec = nc_device_init(&dev->core, &dev->pl);
    if (ec != NABTO_EC_OK) {
        dev->closing = true;
        nabto_device_threads_cond_signal(dev->eventCond);
        nabto_device_platform_signal(&dev->pl);
        nabto_device_threads_join(dev->coreThread);
        nabto_device_threads_join(dev->networkThread);
        nabto_device_free_threads(dev);
        nabto_device_platform_close(&dev->pl);
        free(dev);
        return NULL;
    }

    return (NabtoDevice*)dev;
}

/**
 * block until no further work is done.
 */
void nabto_device_stop(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    nabto_device_threads_mutex_lock(dev->eventMutex);

    nc_device_deinit(&dev->core);

    dev->closing = true;
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    // Send a signal if a function is blocking the network thread.
    nabto_device_platform_signal(&dev->pl);

    nabto_device_threads_cond_signal(dev->eventCond);

    if (dev->networkThread != NULL) {
        nabto_device_threads_join(dev->networkThread);
    }
    if (dev->coreThread != NULL) {
        nabto_device_threads_join(dev->coreThread);
    }

    nabto_device_platform_close(&dev->pl);

}

/**
 * free device when closed
 */
void NABTO_DEVICE_API nabto_device_free(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    nabto_device_free_threads(dev);

    free(dev->productId);
    free(dev->deviceId);
    free(dev->serverUrl);
    free(dev->publicKey);
    free(dev->privateKey);

    free(dev);
}

/**
 * Self explanetory set functions
 */
NabtoDeviceError NABTO_DEVICE_API nabto_device_set_product_id(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    free(dev->productId);

    dev->productId = strdup(str);
    if (dev->productId == NULL) {
        ec = NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return ec;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_device_id(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    free(dev->deviceId);

    dev->deviceId = strdup(str);
    if (dev->deviceId == NULL) {
        ec = NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_server_url(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    free(dev->serverUrl);

    dev->serverUrl = strdup(str);
    if (dev->serverUrl == NULL) {
        ec = NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_server_port(NabtoDevice* device, uint16_t port)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    dev->core.serverPort = port;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_private_key(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    free(dev->privateKey);

    dev->privateKey = strdup(str);
    if (dev->privateKey == NULL) {
        ec = NABTO_DEVICE_EC_OUT_OF_MEMORY;
    } else {
        char* crt;
        ec = nm_dtls_create_crt_from_private_key(dev->privateKey, &crt);
        if (dev->publicKey != NULL) {
            free(dev->publicKey);
            dev->publicKey = NULL;
        }
        dev->publicKey = crt;
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);

}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_app_name(NabtoDevice* device, const char* name)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    if (strlen(name) > 32) {
        return NABTO_DEVICE_EC_STRING_TOO_LONG;
    }
    nabto_device_threads_mutex_lock(dev->eventMutex);
    memcpy(dev->appName, name, strlen(name));
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_app_version(NabtoDevice* device, const char* version)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    if (strlen(version) > 32) {
        return NABTO_DEVICE_EC_STRING_TOO_LONG;
    }
    nabto_device_threads_mutex_lock(dev->eventMutex);
    memcpy(dev->appVersion, version, strlen(version));
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_local_port(NabtoDevice* device, uint16_t port)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    dev->port = port;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_get_local_port(NabtoDevice* device, uint16_t* port)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    uint16_t p = 0;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    p = nc_udp_dispatch_get_local_port(&dev->core.udp);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    if (p == 0) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    } else {
        *port = p;
    }
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_enable_mdns(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    dev->enableMdns = true;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_enable_tcp_tunnelling(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nm_tcptunnels_init(&dev->tcptunnels, &dev->core);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

/**
 * Starting the device
 */
NabtoDeviceError NABTO_DEVICE_API nabto_device_start(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    if (dev->publicKey == NULL || dev->privateKey == NULL || dev->serverUrl == NULL) {
        NABTO_LOG_ERROR(LOG, "Encryption key pair or server URL not set");
        return NABTO_DEVICE_EC_INVALID_STATE;
    }
    if (dev->deviceId == NULL || dev->productId == NULL) {
        NABTO_LOG_ERROR(LOG, "Missing deviceId or productdId");
        return NABTO_DEVICE_EC_INVALID_STATE;
    }


    nabto_device_threads_mutex_lock(dev->eventMutex);
    // Init platform
    nc_device_set_keys(&dev->core, (const unsigned char*)dev->publicKey, strlen(dev->publicKey), (const unsigned char*)dev->privateKey, strlen(dev->privateKey));

    // start the core
    ec = nc_device_start(&dev->core, dev->appName, dev->appVersion, dev->productId, dev->deviceId, dev->serverUrl, stunHost, dev->port, dev->enableMdns);

    if ( ec != NABTO_EC_OK ) {
        NABTO_LOG_ERROR(LOG, "Failed to start device core");
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_get_device_fingerprint_hex(NabtoDevice* device, char** fingerprint)
{
    *fingerprint = NULL;
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (dev->privateKey == NULL) {
        ec = NABTO_DEVICE_EC_INVALID_STATE;
    }
    ec = nm_dtls_get_fingerprint_from_private_key(dev->privateKey, fingerprint);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_client_fingerprint_hex(NabtoDevice* device, NabtoDeviceConnectionRef connectionRef, char** fp)
{
    *fp = NULL;
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    uint8_t clientFingerprint[16];

    struct nc_client_connection* connection = nc_device_connection_from_ref(&dev->core, connectionRef);

    if (connection == NULL || nc_client_connection_get_client_fingerprint(connection, clientFingerprint) != NABTO_EC_OK) {
        ec = NABTO_EC_INVALID_CONNECTION;
    } else {

        *fp = malloc(33);
        memset(*fp, 0, 33);
        uint8_t* f = clientFingerprint;
        sprintf(*fp, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7],
                f[8], f[9], f[10], f[11], f[12], f[13], f[14], f[15]);
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

/**
 * Connection event listener
 */

const int NABTO_DEVICE_CONNECTION_EVENT_OPENED = (int)NC_CONNECTION_EVENT_OPENED;
const int NABTO_DEVICE_CONNECTION_EVENT_CLOSED = (int)NC_CONNECTION_EVENT_CLOSED;
const int NABTO_DEVICE_CONNECTION_EVENT_CHANNEL_CHANGED = (int)NC_CONNECTION_EVENT_CHANNEL_CHANGED;

struct nabto_device_listen_connection_event{
    NabtoDeviceConnectionRef coreRef;
    NabtoDeviceConnectionEvent coreEvent;
};

struct nabto_device_listen_connection_context {
    struct nc_connection_events_listener coreListener;
    struct nabto_device_context* dev;
    struct nabto_device_listener* listener;
    NabtoDeviceConnectionRef* userRef;
    NabtoDeviceConnectionEvent* userEvent;
};

np_error_code nabto_device_connection_events_listener_cb(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData)
{
    struct nabto_device_listen_connection_context* ctx = (struct nabto_device_listen_connection_context*)listenerData;
    np_error_code retEc;
    if (ec == NABTO_EC_OK) {
        struct nabto_device_listen_connection_event* ev = (struct nabto_device_listen_connection_event*)eventData;
        if (ctx->userRef != NULL) {
            retEc = NABTO_EC_OK;
            *ctx->userRef = ev->coreRef;
            *ctx->userEvent = ev->coreEvent;
            ctx->userRef = NULL;
            ctx->userEvent = NULL;
        } else {
            NABTO_LOG_ERROR(LOG, "Tried to resolve connection event but reference was invalid");
            retEc = NABTO_EC_UNKNOWN;
        }
        free(ev);
    } else if (ec == NABTO_EC_ABORTED) {
        nc_device_remove_connection_events_listener(&ctx->dev->core, &ctx->coreListener);
        free(ctx);
        retEc = ec;
    } else {
        free(eventData);
        retEc = ec;
    }
    return retEc;
}

void nabto_device_connection_events_core_cb(uint64_t connectionRef, enum nc_connection_event event, void* userData)
{
    struct nabto_device_listen_connection_context* ctx = (struct nabto_device_listen_connection_context*)userData;
    struct nabto_device_listen_connection_event* ev = (struct nabto_device_listen_connection_event*)calloc(1, sizeof(struct nabto_device_listen_connection_event));
    if (ev == NULL) {
        nabto_device_listener_set_error_code(ctx->listener, NABTO_EC_OUT_OF_MEMORY);
        return;
    }
    ev->coreRef = connectionRef;
    ev->coreEvent = (int)event;
    np_error_code ec = nabto_device_listener_add_event(ctx->listener, ev);
    if (ec != NABTO_EC_OK) {
        free(ev);
    }
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_connection_events_init_listener(NabtoDevice* device, NabtoDeviceListener* deviceListener)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_listen_connection_context* ctx = (struct nabto_device_listen_connection_context*)calloc(1, sizeof(struct nabto_device_listen_connection_context));
    if (ctx == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec = nabto_device_listener_init(dev, listener, NABTO_DEVICE_LISTENER_TYPE_CONNECTION_EVENTS, &nabto_device_connection_events_listener_cb, ctx);
    if (ec) {
        free(ctx);
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_error_core_to_api(ec);
    }
    ctx->dev = dev;
    ctx->listener = listener;
    nc_device_add_connection_events_listener(&dev->core, &ctx->coreListener, &nabto_device_connection_events_core_cb, ctx);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

void NABTO_DEVICE_API nabto_device_listener_connection_event(NabtoDeviceListener* deviceListener, NabtoDeviceFuture* future, NabtoDeviceConnectionRef* ref, NabtoDeviceConnectionEvent* event)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_context* dev = listener->dev;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec = nabto_device_listener_get_status(listener);
    if (nabto_device_listener_get_type(listener) != NABTO_DEVICE_LISTENER_TYPE_CONNECTION_EVENTS) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_future_resolve(fut, NABTO_DEVICE_EC_INVALID_ARGUMENT);
    }
    if (ec != NABTO_EC_OK) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_future_resolve(fut, nabto_device_error_core_to_api(ec));
    }
    struct nabto_device_listen_connection_context* ctx = (struct nabto_device_listen_connection_context*)nabto_device_listener_get_listener_data(listener);
    if (ctx->userRef != NULL) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    }
    ctx->userRef = ref;
    ctx->userEvent = event;
    // user references must be set before as this call can resolve the future to the future queue
    ec = nabto_device_listener_init_future(listener, fut);
    if (ec != NABTO_EC_OK) {
        // resetting user references if future could not be created
        ctx->userRef = NULL;
        ctx->userEvent = NULL;
        nabto_device_future_resolve(fut, ec);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}


/**
 * Device event listener
 */

const int NABTO_DEVICE_EVENT_ATTACHED = (int)NC_DEVICE_EVENT_ATTACHED;
const int NABTO_DEVICE_EVENT_DETACHED = (int)NC_DEVICE_EVENT_DETACHED;

struct nabto_device_listen_device_event{
    NabtoDeviceEvent coreEvent;
};

struct nabto_device_listen_device_context {
    struct nc_device_events_listener coreListener;
    struct nabto_device_context* dev;
    struct nabto_device_listener* listener;
    NabtoDeviceEvent* userEvent;
};

np_error_code nabto_device_events_listener_cb(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData)
{
    struct nabto_device_listen_device_context* ctx = (struct nabto_device_listen_device_context*)listenerData;
    np_error_code retEc;
    if (ec == NABTO_EC_OK) {
        struct nabto_device_listen_device_event* ev = (struct nabto_device_listen_device_event*)eventData;
        if (ctx->userEvent != NULL) {
            retEc = NABTO_EC_OK;
            *ctx->userEvent = ev->coreEvent;
            ctx->userEvent = NULL;
        } else {
            NABTO_LOG_ERROR(LOG, "Tried to resolve device event but reference was invalid");
            retEc = NABTO_EC_UNKNOWN;
        }
        free(ev);
    } else if (ec == NABTO_EC_ABORTED) {
        nc_device_remove_device_events_listener(&ctx->dev->core, &ctx->coreListener);
        free(ctx);
        retEc = ec;
    } else {
        free(eventData);
        retEc = ec;
    }
    return retEc;
}

void nabto_device_events_core_cb(enum nc_device_event event, void* userData)
{
    struct nabto_device_listen_device_context* ctx = (struct nabto_device_listen_device_context*)userData;
    struct nabto_device_listen_device_event* ev = (struct nabto_device_listen_device_event*)calloc(1, sizeof(struct nabto_device_listen_device_event));
    if (ev == NULL) {
        nabto_device_listener_set_error_code(ctx->listener, NABTO_EC_OUT_OF_MEMORY);
        return;
    }
    ev->coreEvent = (int)event;
    np_error_code ec = nabto_device_listener_add_event(ctx->listener, ev);
    if (ec != NABTO_EC_OK) {
        free(ev);
    }
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_device_events_init_listener(NabtoDevice* device, NabtoDeviceListener* deviceListener)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_listen_device_context* ctx = (struct nabto_device_listen_device_context*)calloc(1, sizeof(struct nabto_device_listen_device_context));
    if (ctx == NULL) {
        return NABTO_DEVICE_EC_OUT_OF_MEMORY;
    }
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec = nabto_device_listener_init(dev, listener, NABTO_DEVICE_LISTENER_TYPE_DEVICE_EVENTS, &nabto_device_events_listener_cb, ctx);
    if (ec) {
        free(ctx);
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_error_core_to_api(ec);
    }
    ctx->dev = dev;
    ctx->listener = listener;
    nc_device_add_device_events_listener(&dev->core, &ctx->coreListener, &nabto_device_events_core_cb, ctx);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

void NABTO_DEVICE_API nabto_device_listener_device_event(NabtoDeviceListener* deviceListener, NabtoDeviceFuture* future, NabtoDeviceEvent* event)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_context* dev = listener->dev;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (nabto_device_listener_get_type(listener) != NABTO_DEVICE_LISTENER_TYPE_DEVICE_EVENTS) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_future_resolve(fut, NABTO_DEVICE_EC_INVALID_ARGUMENT);
    }
    np_error_code ec = nabto_device_listener_get_status(listener);
    if (ec != NABTO_EC_OK) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_future_resolve(fut, nabto_device_error_core_to_api(ec));
    }
    struct nabto_device_listen_device_context* ctx = (struct nabto_device_listen_device_context*)nabto_device_listener_get_listener_data(listener);
    if (ctx->userEvent != NULL) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OPERATION_IN_PROGRESS);
    }
    ctx->userEvent = event;

    // user references must be set before as this call can resolve the future to the future queue
    ec = nabto_device_listener_init_future(listener, fut);
    if (ec != NABTO_EC_OK) {
        // resetting user references if future could not be created
        ctx->userEvent = NULL;
        nabto_device_future_resolve(fut, ec);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

/**
 * Closing the device
 */
void nabto_device_close_cb(const np_error_code ec, void* data)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)data;
    nabto_device_future_resolve(dev->closeFut, nabto_device_error_core_to_api(ec));
}

void NABTO_DEVICE_API nabto_device_close(NabtoDevice* device, NabtoDeviceFuture* future)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(dev->eventMutex);
    dev->closeFut = fut;
    np_error_code ec = nc_device_close(&dev->core, &nabto_device_close_cb, dev);
    if (ec != NABTO_EC_OK) {
        nabto_device_future_resolve(fut, ec);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}


NabtoDeviceError NABTO_DEVICE_API nabto_device_set_log_callback(NabtoDevice* device, NabtoDeviceLogCallback cb, void* data)
{
    nm_api_logging_set_callback(cb, data);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_log_level(NabtoDevice* device, const char* level)
{
    uint32_t l = 0;
    if (strcmp(level, "error") == 0) {
        l = NABTO_LOG_SEVERITY_LEVEL_ERROR;
    } else if (strcmp(level, "warn") == 0) {
        l = NABTO_LOG_SEVERITY_LEVEL_WARN;
    } else if (strcmp(level, "info") == 0) {
        l = NABTO_LOG_SEVERITY_LEVEL_INFO;
    } else if (strcmp(level, "trace") == 0) {
        l = NABTO_LOG_SEVERITY_LEVEL_TRACE;
    } else {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }
    nm_api_logging_set_level(l);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_log_std_out_callback(NabtoDevice* device)
{
    nm_api_logging_set_callback(&nm_api_logging_std_out_callback, NULL);
    return NABTO_DEVICE_EC_OK;
}



/*
 * Thread running the network
 */
void* nabto_device_network_thread(void* data)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)data;
    int nfds;
    while(true) {
        nfds = nabto_device_platform_inf_wait();
        nabto_device_threads_mutex_lock(dev->eventMutex);
        nabto_device_platform_read(nfds);
        nabto_device_threads_cond_signal(dev->eventCond);
        if (dev->closing && nabto_device_platform_finished()) {
            nabto_device_threads_mutex_unlock(dev->eventMutex);
            return NULL;
        }
        nabto_device_threads_mutex_unlock(dev->eventMutex);
    }
    return NULL;
}

/*
 * Thread running the core
 */
void* nabto_device_core_thread(void* data)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)data;
    while (true) {
        bool end = false;
        nabto_device_threads_mutex_lock(dev->eventMutex);
        np_event_queue_execute_all(&dev->pl);
        nabto_device_threads_mutex_unlock(dev->eventMutex);

        nabto_api_future_queue_execute_all(dev);

        nabto_device_threads_mutex_lock(dev->eventMutex);
        if (np_event_queue_has_ready_event(&dev->pl)) {
            NABTO_LOG_TRACE(LOG, "future execution added events, not waiting");
        } else if (!nabto_api_future_queue_is_empty(dev)) {
            // Not waiting
        } else if (np_event_queue_has_timed_event(&dev->pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&dev->pl);
            nabto_device_threads_cond_timed_wait(dev->eventCond, dev->eventMutex, ms);
        } else if (dev->closing &&
                   np_event_queue_is_event_queue_empty(&dev->pl) &&
                   !np_event_queue_has_timed_event(&dev->pl) &&
                   nabto_api_future_queue_is_empty(dev))
        {
            end = true;
        } else {
            NABTO_LOG_TRACE(LOG, "no timed events, waits for signals forever");
            nabto_device_threads_cond_wait(dev->eventCond, dev->eventMutex);
        }

        nabto_device_threads_mutex_unlock(dev->eventMutex);

        if (end) {
            return NULL;
        }
    }

    return NULL;
}

void nabto_device_free_threads(struct nabto_device_context* dev)
{
    if (dev->coreThread) {
        nabto_device_threads_free_thread(dev->coreThread);
        dev->coreThread = NULL;
    }
    if (dev->networkThread) {
        nabto_device_threads_free_thread(dev->networkThread);
        dev->networkThread = NULL;
    }
    if (dev->eventMutex) {
        nabto_device_threads_free_mutex(dev->eventMutex);
        dev->eventMutex = NULL;
    }
    if (dev->eventCond) {
        nabto_device_threads_free_cond(dev->eventCond);
        dev->eventCond = NULL;
    }
    if (dev->futureQueueMutex) {
        nabto_device_threads_free_mutex(dev->futureQueueMutex);
        dev->futureQueueMutex = NULL;
    }
}
