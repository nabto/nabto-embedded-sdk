#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include <api/nabto_device_defines.h>
#include <api/nabto_device_stream.h>
#include <api/nabto_device_coap.h>
#include <api/nabto_api_future_queue.h>
#include <api/nabto_platform.h>
#include <platform/np_error_code.h>

#include <platform/np_logging.h>
#include <platform/np_error_code.h>
#include <core/nc_version.h>
#include <core/nc_client_connect.h>

#include <modules/logging/api/nm_api_logging.h>
#include <modules/dtls/nm_dtls_util.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

// TODO: Take though api or something
const char* stunHost = "stun.nabto.net";

void* nabto_device_network_thread(void* data);
void* nabto_device_core_thread(void* data);
void nabto_device_init_platform(struct np_platform* pl);
NabtoDeviceFuture* nabto_device_future_new(NabtoDevice* dev);
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
    memset(dev, 0, sizeof(struct nabto_device_context));

    nabto_device_init_platform(&dev->pl);
    nabto_device_init_platform_modules(&dev->pl);
    nc_device_init(&dev->core, &dev->pl);
    np_event_queue_init(&dev->pl, &notify_event_queue_post, dev);
    dev->closing = false;
    dev->eventMutex = nabto_device_threads_create_mutex();
    if (dev->eventMutex == NULL) {
        NABTO_LOG_ERROR(LOG, "mutex init has failed");
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
    dev->closing = true;

    if (dev->enableMdns) {
        nm_mdns_deinit(&dev->mdns);
    }

    // TODO: reintroduce this through the udp platform as to not leak buffers
    //nm_epoll_close(&dev->pl);
    if (dev->networkThread != NULL) {
        nabto_device_threads_join(dev->networkThread);
    }
    if (dev->coreThread != NULL) {
        nabto_device_threads_join(dev->coreThread);
    }

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

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_private_key(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    free(dev->privateKey);

    dev->privateKey = strdup(str);
    if (dev->privateKey == NULL) {
        // TODO
        ec = NABTO_EC_FAILED;
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
        return NABTO_DEVICE_EC_FAILED;
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
        return NABTO_DEVICE_EC_FAILED;
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
    nabto_device_threads_mutex_lock(dev->eventMutex);
    *port = nc_udp_dispatch_get_local_port(&dev->core.udp);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

uint16_t mdns_get_port(void* userData)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)userData;
    return nc_udp_dispatch_get_local_port(&dev->core.udp);
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
        return NABTO_DEVICE_EC_FAILED;
    }
    if (dev->deviceId == NULL || dev->productId == NULL) {
        NABTO_LOG_ERROR(LOG, "Missing deviceId or productdId");
        return NABTO_DEVICE_EC_FAILED;
    }
    dev->eventCond = nabto_device_threads_create_condition();
    if (dev->eventCond == NULL) {
        NABTO_LOG_ERROR(LOG, "condition init has failed");
        nabto_device_free_threads(dev);
        return NABTO_DEVICE_EC_FAILED;
    }
    dev->coreThread = nabto_device_threads_create_thread();
    dev->networkThread = nabto_device_threads_create_thread();
    if (dev->coreThread == NULL || dev->networkThread == NULL) {
        nabto_device_free_threads(dev);
    }

    nabto_device_threads_mutex_lock(dev->eventMutex);
    // Init platform
    nabto_device_init_dtls_modules(&dev->pl, dev->publicKey, dev->privateKey);
    // start the core
    ec = nc_device_start(&dev->core, dev->appName, dev->appVersion, dev->productId, dev->deviceId, dev->serverUrl, stunHost, dev->port);

    if ( ec != NABTO_EC_OK ) {
        NABTO_LOG_ERROR(LOG, "Failed to start device core");
        nabto_device_free_threads(dev);
        return nabto_device_error_core_to_api(ec);
    }
    if (nabto_device_threads_run(dev->coreThread, nabto_device_core_thread, dev) != 0) {
        NABTO_LOG_ERROR(LOG, "Failed to create thread");
        nabto_device_free_threads(dev);
        return NABTO_DEVICE_EC_FAILED;
    }
    if (nabto_device_threads_run(dev->networkThread, nabto_device_network_thread, dev) != 0) {
        NABTO_LOG_ERROR(LOG, "Failed to create thread");
        nabto_device_free_threads(dev);
        return NABTO_DEVICE_EC_FAILED;
    }

    if (dev->enableMdns) {
        nm_mdns_init(&dev->mdns, &dev->pl, dev->productId, dev->deviceId, mdns_get_port, dev);
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}


NabtoDeviceError NABTO_DEVICE_API nabto_device_get_device_fingerprint_hex(NabtoDevice* device, char** fingerprint)
{
    *fingerprint = NULL;
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (dev->privateKey == NULL) {
        // TODO better ec
        ec = NABTO_EC_FAILED;
    }
    ec = nm_dtls_get_fingerprint_from_private_key(dev->privateKey, fingerprint);

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
    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    dev->closeFut = fut;
    nc_device_close(&dev->core, &nabto_device_close_cb, dev);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return fut;
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
        nfds = dev->pl.udp.inf_wait();
        nabto_device_threads_mutex_lock(dev->eventMutex);
        if (nfds > 0) {
            dev->pl.udp.read(nfds);
        }
        NABTO_LOG_TRACE(LOG, "Network thread signalling core thread");
        nabto_device_threads_cond_signal(dev->eventCond);
        if (dev->closing) {
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
        nabto_device_threads_mutex_lock(dev->eventMutex);
        np_event_queue_execute_all(&dev->pl);
        nabto_device_threads_mutex_unlock(dev->eventMutex);

        nabto_api_future_queue_execute_all(&dev->queueHead);
        if (dev->closing) {
            return NULL;
        }

        nabto_device_threads_mutex_lock(dev->eventMutex);
//        np_event_queue_execute_all(&dev->pl);
        if (np_event_queue_has_ready_event(&dev->pl)) {
            NABTO_LOG_TRACE(LOG, "future execution added events, not waiting");
        } else if (np_event_queue_has_timed_event(&dev->pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&dev->pl);
            NABTO_LOG_TRACE(LOG, "Found timed events, waits %u ms for signals", ms);
            nabto_device_threads_cond_timed_wait(dev->eventCond, dev->eventMutex, ms);
            NABTO_LOG_TRACE(LOG, "Core thread timed wait returned");
        } else {

            NABTO_LOG_TRACE(LOG, "no timed events, waits for signals forever");
            nabto_device_threads_cond_wait(dev->eventCond, dev->eventMutex);
        }
        nabto_device_threads_mutex_unlock(dev->eventMutex);
        if (dev->closing) {
            return NULL;
        }
    }

    return NULL;
}

/*
 * Posting futures for resolving on the future queue
 */
void nabto_device_post_future(NabtoDevice* device, NabtoDeviceFuture* fut) {
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_api_future_queue_post(&dev->queueHead, fut);
}

void nabto_device_free_threads(struct nabto_device_context* dev)
{
    if (dev->coreThread) {
        nabto_device_threads_free_thread(dev->coreThread);
    }
    if (dev->networkThread) {
        nabto_device_threads_free_thread(dev->networkThread);
    }
    if (dev->eventMutex) {
        nabto_device_threads_free_mutex(dev->eventMutex);
    }
    if (dev->eventCond) {
        nabto_device_threads_free_cond(dev->eventCond);
    }
}

NabtoDeviceError nabto_device_error_core_to_api(np_error_code ec)
{
    switch (ec) {
        case NABTO_EC_OK: return NABTO_DEVICE_EC_OK;
        case NABTO_EC_FAILED: return NABTO_DEVICE_EC_FAILED;
        case NABTO_EC_OUT_OF_MEMORY: return NABTO_DEVICE_EC_OUT_OF_MEMORY;
        case NABTO_EC_NOT_FOUND: return NABTO_DEVICE_EC_NOT_FOUND;
        default: return NABTO_DEVICE_EC_FAILED;
    }
}
