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
// TODO consider returning NabtoDeviceError and take NabtoDevice**
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
    dev->futureQueueCond = nabto_device_threads_create_condition();
    if (dev->futureQueueCond == NULL) {
        NABTO_LOG_ERROR(LOG, "Future queue condition init has failed");
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
 * free device when closed
 */
void NABTO_DEVICE_API nabto_device_free(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->futureQueueMutex);
    if (dev->queueHead != NULL) {
        // future queue not empty, waiting for it to finish
        // Since we got the lock, the core thread must be waiting so we signal before we wait
        NABTO_LOG_TRACE(LOG, "got future mutex but futures are still left");
        nabto_device_threads_cond_signal(dev->eventCond);
        nabto_device_threads_cond_wait(dev->futureQueueCond, dev->futureQueueMutex);
    }
    nabto_device_threads_mutex_lock(dev->eventMutex);

    nc_device_deinit(&dev->core);

    dev->closing = true;
    nabto_device_coap_free_resources(dev);
    nabto_device_threads_mutex_unlock(dev->futureQueueMutex);
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

    nabto_device_free_threads(dev);
    nabto_device_platform_close(&dev->pl);

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

void nabto_device_connection_events_listener_cb(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData)
{
    struct nabto_device_listen_connection_context* ctx = (struct nabto_device_listen_connection_context*)listenerData;
    if (ec == NABTO_EC_OK) {
        struct nabto_device_listen_connection_event* ev = (struct nabto_device_listen_connection_event*)eventData;
        if (ctx->userRef != NULL) {
            nabto_api_future_set_error_code(future, NABTO_DEVICE_EC_OK);
            *ctx->userRef = ev->coreRef;
            *ctx->userEvent = ev->coreEvent;
            ctx->userRef = NULL;
            ctx->userEvent = NULL;
        } else {
            NABTO_LOG_ERROR(LOG, "Tried to resolve connection event but reference was invalid");
            nabto_api_future_set_error_code(future, NABTO_DEVICE_EC_FAILED);
        }
        free(ev);
    } else if (ec == NABTO_EC_ABORTED) {
        nc_device_remove_connection_events_listener(&ctx->dev->core, &ctx->coreListener);
        free(ctx);
    } else {
        free(eventData);
    }
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

NabtoDeviceListener* NABTO_DEVICE_API nabto_device_connection_events_listener_new(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_listen_connection_context* ctx = (struct nabto_device_listen_connection_context*)calloc(1, sizeof(struct nabto_device_listen_connection_context));
    if (ctx == NULL) {
        return NULL;
    }
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_listener* listener = nabto_device_listener_new(dev, NABTO_DEVICE_LISTENER_TYPE_CONNECTION_EVENTS, &nabto_device_connection_events_listener_cb, ctx);
    if (listener == NULL) {
        free(ctx);
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return NULL;
    }
    ctx->dev = dev;
    ctx->listener = listener;
    nc_device_add_connection_events_listener(&dev->core, &ctx->coreListener, &nabto_device_connection_events_core_cb, ctx);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return (NabtoDeviceListener*)listener;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_listener_connection_event(NabtoDeviceListener* deviceListener, NabtoDeviceFuture** future, NabtoDeviceConnectionRef* ref, NabtoDeviceConnectionEvent* event)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_context* dev = listener->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec = nabto_device_listener_get_status(listener);
    if (nabto_device_listener_get_type(listener) != NABTO_DEVICE_LISTENER_TYPE_CONNECTION_EVENTS) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return NABTO_DEVICE_EC_INVALID_LISTENER;
    }
    if (ec != NABTO_EC_OK) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_error_core_to_api(ec);
    }
    struct nabto_device_listen_connection_context* ctx = (struct nabto_device_listen_connection_context*)nabto_device_listener_get_listener_data(listener);
    if (ctx->userRef != NULL) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return NABTO_DEVICE_EC_OPERATION_IN_PROGRESS;
    }
    ctx->userRef = ref;
    ctx->userEvent = event;
    struct nabto_device_future* fut;
    // user references must be set before as this call can resolve the future to the future queue
    ec = nabto_device_listener_create_future(listener, &fut);
    if (ec != NABTO_EC_OK) {
        // resetting user references if future could not be created
        ctx->userRef = NULL;
        ctx->userEvent = NULL;
    } else {
        *future = (NabtoDeviceFuture*)fut;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}


/**
 * Device event listener
 */

const int NABTO_DEVICE_EVENT_ATTACHED = (int)NC_DEVICE_EVENT_ATTACHED;
const int NABTO_DEVICE_EVENT_DETACHED = (int)NC_DEVICE_EVENT_DETACHED;
const int NABTO_DEVICE_EVENT_FAILURE = (int)NC_DEVICE_EVENT_FAILURE;

struct nabto_device_listen_device_event{
    NabtoDeviceEvent coreEvent;
};

struct nabto_device_listen_device_context {
    struct nc_device_events_listener coreListener;
    struct nabto_device_context* dev;
    struct nabto_device_listener* listener;
    NabtoDeviceEvent* userEvent;
};

void nabto_device_events_listener_cb(const np_error_code ec, struct nabto_device_future* future, void* eventData, void* listenerData)
{
    struct nabto_device_listen_device_context* ctx = (struct nabto_device_listen_device_context*)listenerData;
    if (ec == NABTO_EC_OK) {
        struct nabto_device_listen_device_event* ev = (struct nabto_device_listen_device_event*)eventData;
        if (ctx->userEvent != NULL) {
            nabto_api_future_set_error_code(future, NABTO_DEVICE_EC_OK);
            *ctx->userEvent = ev->coreEvent;
            ctx->userEvent = NULL;
        } else {
            NABTO_LOG_ERROR(LOG, "Tried to resolve device event but reference was invalid");
            nabto_api_future_set_error_code(future, NABTO_DEVICE_EC_FAILED);
        }
        free(ev);
    } else if (ec == NABTO_EC_ABORTED) {
        nc_device_remove_device_events_listener(&ctx->dev->core, &ctx->coreListener);
        free(ctx);
    } else {
        free(eventData);
    }
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

NabtoDeviceListener* NABTO_DEVICE_API nabto_device_device_events_listener_new(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_listen_device_context* ctx = (struct nabto_device_listen_device_context*)calloc(1, sizeof(struct nabto_device_listen_device_context));
    if (ctx == NULL) {
        return NULL;
    }
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_listener* listener = nabto_device_listener_new(dev, NABTO_DEVICE_LISTENER_TYPE_DEVICE_EVENTS, &nabto_device_events_listener_cb, ctx);
    if (listener == NULL) {
        free(ctx);
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return NULL;
    }
    ctx->dev = dev;
    ctx->listener = listener;
    nc_device_add_device_events_listener(&dev->core, &ctx->coreListener, &nabto_device_events_core_cb, ctx);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return (NabtoDeviceListener*)listener;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_listener_device_event(NabtoDeviceListener* deviceListener, NabtoDeviceFuture** future, NabtoDeviceEvent* event)
{
    struct nabto_device_listener* listener = (struct nabto_device_listener*)deviceListener;
    struct nabto_device_context* dev = listener->dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (nabto_device_listener_get_type(listener) != NABTO_DEVICE_LISTENER_TYPE_DEVICE_EVENTS) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return NABTO_DEVICE_EC_INVALID_LISTENER;
    }
    np_error_code ec = nabto_device_listener_get_status(listener);
    if (ec != NABTO_EC_OK) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return nabto_device_error_core_to_api(ec);
    }
    struct nabto_device_listen_device_context* ctx = (struct nabto_device_listen_device_context*)nabto_device_listener_get_listener_data(listener);
    if (ctx->userEvent != NULL) {
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        return NABTO_DEVICE_EC_OPERATION_IN_PROGRESS;
    }
    ctx->userEvent = event;
    struct nabto_device_future* fut;
    // user references must be set before as this call can resolve the future to the future queue
    ec = nabto_device_listener_create_future(listener, &fut);
    if (ec != NABTO_EC_OK) {
        // resetting user references if future could not be created
        ctx->userEvent = NULL;
    } else {
        *future = (NabtoDeviceFuture*)fut;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

/**
 * Closing the device
 */
void nabto_device_close_cb(const np_error_code ec, void* data)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)data;
    nabto_api_future_set_error_code(dev->closeFut, nabto_device_error_core_to_api(ec));
    nabto_api_future_queue_post(&dev->queueHead, dev->closeFut);
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_close(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nabto_device_future* fut = nabto_device_future_new(dev);
    dev->closeFut = fut;
    nc_device_close(&dev->core, &nabto_device_close_cb, dev);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return (NabtoDeviceFuture*)fut;
}


NabtoDeviceError NABTO_DEVICE_API nabto_device_log_set_callback(NabtoDevice* device, NabtoDeviceLogCallback cb, void* data)
{
    nm_api_logging_set_callback(cb, data);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_log_set_level(NabtoDevice* device, const char* level)
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
        return NABTO_DEVICE_EC_INVALID_LOG_LEVEL;
    }
    nm_api_logging_set_level(l);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_log_set_std_out_callback(NabtoDevice* device)
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
        nabto_device_threads_mutex_lock(dev->futureQueueMutex);
        nabto_device_threads_mutex_lock(dev->eventMutex);
        np_event_queue_execute_all(&dev->pl);
        nabto_device_threads_mutex_unlock(dev->eventMutex);

        nabto_api_future_queue_execute_all(&dev->queueHead);
        nabto_device_threads_cond_signal(dev->futureQueueCond);
        nabto_device_threads_mutex_unlock(dev->futureQueueMutex);
        if (dev->closing) {
            return NULL;
        }

        nabto_device_threads_mutex_lock(dev->eventMutex);
//        np_event_queue_execute_all(&dev->pl);
        if (np_event_queue_has_ready_event(&dev->pl)) {
            NABTO_LOG_TRACE(LOG, "future execution added events, not waiting");
        } else if (np_event_queue_has_timed_event(&dev->pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&dev->pl);
            nabto_device_threads_cond_timed_wait(dev->eventCond, dev->eventMutex, ms);
        } else {

            NABTO_LOG_TRACE(LOG, "no timed events, waits for signals forever");
            nabto_device_threads_cond_wait(dev->eventCond, dev->eventMutex);
        }
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        /* if (dev->closing) { */
        /*     return NULL; */
        /* } */
    }

    return NULL;
}

/*
 * Posting futures for resolving on the future queue
 */
void nabto_device_post_future(struct nabto_device_context* dev, struct nabto_device_future* fut) {
    nabto_api_future_queue_post(&dev->queueHead, fut);
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
    if (dev->futureQueueCond) {
        nabto_device_threads_free_cond(dev->futureQueueCond);
        dev->futureQueueCond = NULL;
    }
}
