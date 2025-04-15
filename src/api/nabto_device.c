#include <nabto/nabto_device_config.h>
#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include <api/nabto_device_defines.h>
#include <api/nabto_device_stream.h>
#include <api/nabto_device_coap.h>
#include <api/nabto_device_future.h>
#include <api/nabto_device_event_handler.h>
#include <api/nabto_device_platform.h>
#include <api/nabto_device_coap.h>
#include <api/nabto_device_authorization.h>
#include <api/nabto_device_future_queue.h>
#include <api/nabto_device_error.h>
#include <api/nabto_device_logging.h>
#include <platform/np_error_code.h>
#include <platform/np_allocator.h>

#include <platform/np_logging.h>
#include <platform/np_error_code.h>
#include <core/nc_version.h>
#include <core/nc_client_connection.h>

#if defined(NABTO_DEVICE_MBEDTLS)
#include <modules/mbedtls/nm_mbedtls_random.h>
#include <modules/mbedtls/nm_mbedtls_spake2.h>
#include <modules/mbedtls/nm_mbedtls_cli.h>
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
#include <modules/mbedtls/nm_mbedtls_srv.h>
#endif
#include <modules/mbedtls/nm_mbedtls_util.h>
#elif defined(NABTO_DEVICE_WOLFSSL)
#include <modules/wolfssl/nm_wolfssl_random.h>
#include <modules/wolfssl/nm_wolfssl_spake2.h>
#include <modules/wolfssl/nm_wolfssl_cli.h>
#include <modules/wolfssl/nm_wolfssl_util.h>
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
#include <modules/wolfssl/nm_wolfssl_srv.h>
#endif
#else
#error Missing DTLS implementation
#endif

#include <modules/communication_buffer/nm_communication_buffer.h>


#include <nn/string.h>

//#include "nabto_device_event_queue.h"

#define LOG NABTO_LOG_MODULE_API

static const char* defaultServerUrlSuffix = ".devices.nabto.net";

void nabto_device_free_threads(struct nabto_device_context* dev);
void nabto_device_do_stop(struct nabto_device_context* dev);

static void nabto_device_platform_closed_cb(const np_error_code ec, void* userData);

const char* NABTO_DEVICE_API nabto_device_version()
{
    return nc_version();
}

void nabto_device_new_resolve_failure(struct nabto_device_context* dev)
{
    dev->closing = true;
    nabto_device_do_stop(dev);
    nabto_device_free((NabtoDevice*)dev);
}

/**
 * Allocate new device
 */
NabtoDevice* NABTO_DEVICE_API nabto_device_new()
{
    struct nabto_device_context* dev = np_calloc(1, sizeof(struct nabto_device_context));
    np_error_code ec;
    if (dev == NULL) {
        NABTO_LOG_ERROR(LOG, "Could not allocate %d bytes for the device context", sizeof(struct nabto_device_context));
        return NULL;
    }

    dev->closing = false;
    dev->eventMutex = nabto_device_threads_create_mutex();
    if (dev->eventMutex == NULL) {
        NABTO_LOG_ERROR(LOG, "mutex init has failed");
        nabto_device_new_resolve_failure(dev);
        return NULL;
    }

    nabto_device_logging_init();

    struct np_platform* pl = &dev->pl;

    nm_communication_buffer_init(pl);
#ifdef NABTO_DEVICE_MBEDTLS
    nm_mbedtls_cli_init(pl);
    nm_mbedtls_random_init(pl);
#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
    nm_mbedtls_spake2_init(pl);
#endif
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
    nm_mbedtls_srv_init(pl);
#endif
#endif
#ifdef NABTO_DEVICE_WOLFSSL
    nm_wolfssl_cli_init(pl);
    nm_wolfssl_random_init(pl);
#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
    nm_wolfssl_spake2_init(pl);
#endif
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
    nm_wolfssl_srv_init(pl);
#endif
#endif

    ec = nabto_device_platform_init(dev, dev->eventMutex);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to initialize platform modules");
        nabto_device_new_resolve_failure(dev);
        return NULL;
    }

    if (pl->udp.mptr == NULL) {
        NABTO_LOG_ERROR(LOG, "Failed to initialize platform, missing UDP module");
        nabto_device_new_resolve_failure(dev);
        return NULL;
    }

    if (pl->timestamp.mptr == NULL) {
        NABTO_LOG_ERROR(LOG, "Failed to initialize platform, missing timestamp module");
        nabto_device_new_resolve_failure(dev);
        return NULL;
    }

    if (pl->eq.mptr == NULL) {
        NABTO_LOG_ERROR(LOG, "Failed to initialize platform, missing event queue module");
        nabto_device_new_resolve_failure(dev);
        return NULL;
    }

    if (pl->dns.mptr == NULL) {
        NABTO_LOG_ERROR(LOG, "Failed to initialize platform, missing dns module");
        nabto_device_new_resolve_failure(dev);
        return NULL;
    }

    nabto_device_authorization_init_module(dev);

    ec = nc_device_init(&dev->core, &dev->pl);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to initialize device core. %s",  np_error_code_to_string(ec));
        nabto_device_new_resolve_failure(dev);
        return NULL;
    }

    if (pl->tcp.mptr == NULL) {
        NABTO_LOG_INFO(LOG, "No TCP module so not starting the tcp tunnelling functionality");
    } else {
        ec = nm_tcp_tunnels_init(&dev->tcpTunnels, &dev->core);
        if (ec != NABTO_EC_OK) {
            NABTO_LOG_ERROR(LOG, "Failed to start tcp tunnelling module");
            nabto_device_new_resolve_failure(dev);
            return NULL;
        }
    }

    nn_llist_init(&dev->listeners);

#if defined(NABTO_DEVICE_FUTURE_QUEUE)
    ec = nabto_device_future_queue_init(&dev->futureQueue);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to start future_queue");
        nabto_device_new_resolve_failure(dev);
        return NULL;
    }
#endif

    ec = np_completion_event_init(&dev->pl.eq, &dev->platformCloseEvent, nabto_device_platform_closed_cb, dev);
    if (ec != NABTO_EC_OK) {
        nabto_device_new_resolve_failure(dev);
        return NULL;
    }

    return (NabtoDevice*)dev;
}

/**
 * block until no further work is done.
 */
void NABTO_DEVICE_API nabto_device_stop(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    if (dev->closing) {
        return;
    }

    nabto_device_listener_stop_all(dev);

    nabto_device_threads_mutex_lock(dev->eventMutex);

    if (dev->pl.tcp.mptr != NULL) {
        nm_tcp_tunnels_deinit(&dev->tcpTunnels);
    }
    nc_device_stop(&dev->core);

    dev->closing = true;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    nabto_device_do_stop(dev);
}

void nabto_device_do_stop(struct nabto_device_context* dev)
{
    nabto_device_platform_stop_blocking(dev);
#if defined(NABTO_DEVICE_FUTURE_QUEUE)
    nabto_device_future_queue_stop(&dev->futureQueue);
#endif
}

/**
 * free device when closed
 */
void NABTO_DEVICE_API nabto_device_free(NabtoDevice* device)
{
    if (device == NULL) {
        return;
    }
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    nabto_device_stop(device);

    //nabto_device_event_queue_stop(&dev->pl);

    nc_device_deinit(&dev->core);

    np_completion_event_deinit(&dev->platformCloseEvent);


    nabto_device_platform_deinit(dev);
#ifdef NABTO_DEVICE_MBEDTLS
    nm_mbedtls_random_deinit(&dev->pl);
#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
    nm_mbedtls_spake2_deinit(&dev->pl);
#endif
    nm_mbedtls_cli_deinit(&dev->pl);
#endif
#ifdef NABTO_DEVICE_WOLFSSL
    nm_wolfssl_random_deinit(&dev->pl);
#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
    nm_wolfssl_spake2_deinit(&dev->pl);
#endif
    nm_wolfssl_cli_deinit(&dev->pl);
#endif

#if defined(NABTO_DEVICE_FUTURE_QUEUE)
    nabto_device_future_queue_deinit(&dev->futureQueue);
#endif
    nabto_device_free_threads(dev);

    np_free(dev->certificate);
    np_free(dev->privateKey);

    np_free(dev);
}

/**
 * Self explanetory set functions
 */
NabtoDeviceError NABTO_DEVICE_API nabto_device_set_product_id(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec = nc_device_set_product_id(&dev->core, str);
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return nabto_device_error_core_to_api(ec);
}

const char* NABTO_DEVICE_API nabto_device_get_product_id(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    const char* ret = NULL;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ret = dev->core.productId;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ret;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_device_id(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec = nc_device_set_device_id(&dev->core, str);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

const char* NABTO_DEVICE_API nabto_device_get_device_id(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    const char* ret = NULL;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ret = dev->core.deviceId;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ret;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_server_url(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec = nc_device_set_server_url(&dev->core, str);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
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
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_free(dev->privateKey);

    dev->privateKey = nn_strdup(str, np_allocator_get());
    if (dev->privateKey == NULL) {
        ec = NABTO_EC_OUT_OF_MEMORY;
    } else {
        char* crt;
#if defined(NABTO_DEVICE_MBEDTLS)
        ec = nm_mbedtls_create_crt_from_private_key(dev->privateKey, &crt);
#elif defined(NABTO_DEVICE_WOLFSSL)
        ec = nm_wolfssl_create_crt_from_private_key(dev->privateKey, &crt);
#else
#error Missing implementation to create a crt from a private key.
#endif
        if (dev->certificate != NULL) {
            np_free(dev->certificate);
            dev->certificate = NULL;
        }
        dev->certificate = crt;

        if (ec == NABTO_EC_OK) {
#if defined(NABTO_DEVICE_MBEDTLS)
            ec = nm_mbedtls_get_fingerprint_from_private_key(dev->privateKey, dev->fingerprint);
#elif defined(NABTO_DEVICE_WOLFSSL)
            ec = nm_wolfssl_get_fingerprint_from_private_key(dev->privateKey, dev->fingerprint);
#else
#error Missing implementation to create a crt from a private key.
#endif
        }
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
    np_error_code ec = nc_device_set_app_name(&dev->core, name);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

const char* NABTO_DEVICE_API nabto_device_get_app_name(NabtoDevice* device)
{
    // it does not make sense to synchronize this as the result cannot
    // be used in a thread safe manner where the app_name is changed
    // while this function is called.
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    return nc_device_get_app_name(&dev->core);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_app_version(NabtoDevice* device, const char* version)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    if (strlen(version) > 32) {
        return NABTO_DEVICE_EC_STRING_TOO_LONG;
    }

    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec = nc_device_set_app_version(&dev->core, version);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_disable_remote_access(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec = nc_device_disable_remote_access(&dev->core);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);

}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_basestation_attach(NabtoDevice* device, bool enable)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    np_error_code ec = nc_device_set_basestation_attach(&dev->core, enable);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

const char* NABTO_DEVICE_API nabto_device_get_app_version(NabtoDevice* device)
{
    // it does not make sense to synchronize this as the result cannot
    // be used in a thread safe manner where the app_name is changed
    // while this function is called.
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    return nc_device_get_app_version(&dev->core);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_local_port(NabtoDevice* device, uint16_t port)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    dev->core.localPort = port;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_p2p_port(NabtoDevice* device, uint16_t port)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    dev->core.p2pPort = port;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_get_local_port(NabtoDevice* device, uint16_t* port)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    uint16_t p = 0;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    p = nc_udp_dispatch_get_local_port(&dev->core.localUdp);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    if (p == 0) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }
    *port = p;
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_get_p2p_port(NabtoDevice* device, uint16_t* port)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    uint16_t p = 0;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    p = nc_udp_dispatch_get_local_port(&dev->core.udp);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    if (p == 0) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }
    *port = p;
    return NABTO_DEVICE_EC_OK;
}



void nabto_device_start_cb(const np_error_code ec, void* data)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)data;
    nabto_device_future_resolve(dev->startFut, nabto_device_error_core_to_api(ec));
    // TODO nc_device_events_listener_notify(NC_DEVICE_EVENT_CLOSED, &dev->core);
}

/**
 * Starting the device
 */
void NABTO_DEVICE_API nabto_device_start(NabtoDevice* device, NabtoDeviceFuture* future)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);


    nabto_device_threads_mutex_lock(dev->eventMutex);

    NABTO_LOG_TRACE(LOG, "Nabto Embedded SDK Version: %s", nc_version());

    dev->startFut = fut;

    if (dev->certificate == NULL || dev->privateKey == NULL) {
        NABTO_LOG_ERROR(LOG, "Encryption key pair not set");
        nabto_device_future_resolve(fut, NABTO_EC_INVALID_STATE);
    } else {
        np_error_code ec;
        // Init platform
        ec = nc_device_set_keys(&dev->core, (const unsigned char*)dev->certificate, strlen(dev->certificate), (const unsigned char*)dev->privateKey, strlen(dev->privateKey), dev->fingerprint);
        if (ec != NABTO_EC_OK) {
            nabto_device_future_resolve(fut, ec);
        } else {
            // start the core
            ec = nc_device_start(&dev->core, defaultServerUrlSuffix, &nabto_device_start_cb, dev);
            if (ec != NABTO_EC_OK) {
                nabto_device_future_resolve(fut, ec);
            }
        }
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

static char* toHex(uint8_t* data, size_t dataLength)
{
    size_t outputLength = dataLength*2 + 1;
    char* output = (char*)np_calloc(1, outputLength);
    if (output == NULL) {
        return output;
    }
    size_t i;
    for (i = 0; i < dataLength; i++) {
        size_t outputOffset = i*2;
        sprintf(output+outputOffset, "%02x", data[i]);
    }
    return output;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_get_device_fingerprint(NabtoDevice* device, char** fingerprint)
{
    *fingerprint = NULL;
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (dev->privateKey == NULL) {
        ec = NABTO_EC_INVALID_STATE;
    } else {
        *fingerprint = toHex(dev->fingerprint, 32);
        ec = NABTO_EC_OK;
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
        ec = NABTO_EC_INVALID_STATE;
    } else {
        *fingerprint = toHex(dev->fingerprint, 16);
        ec = NABTO_EC_OK;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_get_device_fingerprint_full_hex(NabtoDevice* device, char** fingerprint)
{
    return nabto_device_get_device_fingerprint(device, fingerprint);
}

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_client_fingerprint(NabtoDevice* device, NabtoDeviceConnectionRef connectionRef, char** fp)
{
    *fp = NULL;
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    uint8_t clientFingerprint[32];

    struct nc_connection* connection = nc_device_connection_from_ref(&dev->core, connectionRef);

    if (connection == NULL || !nc_connection_get_client_fingerprint(connection, clientFingerprint)) {
        ec = NABTO_EC_INVALID_CONNECTION;
    } else {
        *fp = toHex(clientFingerprint, 32);
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_client_fingerprint_hex(NabtoDevice* device, NabtoDeviceConnectionRef connectionRef, char** fp)
{
    *fp = NULL;
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    uint8_t clientFingerprint[32];

    struct nc_connection* connection = nc_device_connection_from_ref(&dev->core, connectionRef);

    if (connection == NULL || !nc_connection_get_client_fingerprint(connection, clientFingerprint)) {
        ec = NABTO_EC_INVALID_CONNECTION;
    } else {
        *fp = toHex(clientFingerprint, 16);
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return ec;
}

NABTO_DEVICE_DECL_PREFIX NabtoDeviceError NABTO_DEVICE_API
nabto_device_connection_get_client_fingerprint_full_hex(NabtoDevice* device, NabtoDeviceConnectionRef connectionRef, char** fp)
{
    return nabto_device_connection_get_client_fingerprint(device, connectionRef, fp);
}

NABTO_DEVICE_DECL_PREFIX bool NABTO_DEVICE_API
nabto_device_connection_is_local(NabtoDevice* device,
                                 NabtoDeviceConnectionRef ref)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    bool local = false;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    struct nc_connection* connection = nc_device_connection_from_ref(&dev->core, ref);
    if (connection != NULL) {
        local = nc_connection_is_local(connection);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return local;
}

void nabto_device_closed(struct nabto_device_context* dev, const np_error_code ec)
{
    nabto_device_future_resolve(dev->closeFut, nabto_device_error_core_to_api(ec));
    nc_device_events_listener_notify(NC_DEVICE_EVENT_CLOSED, &dev->core);
    dev->closeFut = NULL;
}

void nabto_device_platform_closed_cb(const np_error_code ec, void* userData)
{
    struct nabto_device_context* dev = userData;
    nabto_device_closed(dev, ec);
}

/**
 * Closing the device
 */
void nabto_device_core_closed_cb(const np_error_code ec, void* data)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)data;
    if (ec != NABTO_EC_OK) {
        nabto_device_closed(dev, ec);
    } else {
        nabto_device_platform_close(dev, &dev->platformCloseEvent);
    }
}

void NABTO_DEVICE_API nabto_device_close(NabtoDevice* device, NabtoDeviceFuture* future)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    if (dev->closeFut != NULL) {
        nabto_device_future_resolve(fut, NABTO_EC_OPERATION_IN_PROGRESS);
        return;
    }
    nabto_device_future_reset(fut);

    nabto_device_threads_mutex_lock(dev->eventMutex);

    dev->closeFut = fut;
    np_error_code ec = nc_device_close(&dev->core, &nabto_device_core_closed_cb, dev);
    if (ec != NABTO_EC_OK) {
        nabto_device_future_resolve(fut, ec);
        dev->closeFut = NULL;
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}


NabtoDeviceError NABTO_DEVICE_API
nabto_device_add_server_connect_token(NabtoDevice* device, const char* serverConnectToken)
{
    if (serverConnectToken == NULL) {
        return NABTO_DEVICE_EC_INVALID_ARGUMENT;
    }
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nc_device_add_server_connect_token(&dev->core, serverConnectToken);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_are_server_connect_tokens_synchronized(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nc_device_is_server_connect_tokens_synchronized(&dev->core);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_create_server_connect_token(NabtoDevice* device, char** serverConnectToken)
{
    const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrtsuvwxyz0123456789";
    size_t alphabetLength = strlen(alphabet);

    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    np_error_code ec;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    struct np_platform* pl = &dev->pl;

    char output[13];
    memset(output, 0, 13);
    size_t generated = 0;
    while (generated < 12) {
        uint8_t randByte;

        ec = pl->random.random(pl, &randByte, 1);
        if (ec) {
            break;
        }
        if (randByte < alphabetLength) {
            output[generated] = alphabet[randByte];
            generated++;
        }
    }

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    if (ec == NABTO_EC_OK) {
        *serverConnectToken = nn_strdup(output, np_allocator_get());
        if (*serverConnectToken == NULL) {
            ec = NABTO_EC_OUT_OF_MEMORY;
        }
    }
    return nabto_device_error_core_to_api(ec);
}


void nabto_device_free_threads(struct nabto_device_context* dev)
{
    if (dev->eventMutex) {
        nabto_device_threads_free_mutex(dev->eventMutex);
        dev->eventMutex = NULL;
    }
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_set_root_certs(NabtoDevice* device, const char* certs)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec;

    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nc_attacher_set_root_certs(&dev->core.attacher, certs);
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_limit_connections(NabtoDevice* device, size_t limit)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    nabto_device_threads_mutex_lock(dev->eventMutex);
    dev->core.connections.maxConcurrentConnections = limit;
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return nabto_device_error_core_to_api(NABTO_EC_OK);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_limit_streams(NabtoDevice* device, size_t limit)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    nabto_device_threads_mutex_lock(dev->eventMutex);
    dev->core.streamManager.maxStreams = limit;
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return nabto_device_error_core_to_api(NABTO_EC_OK);
}

NabtoDeviceError NABTO_DEVICE_API
nabto_device_limit_coap_server_requests(NabtoDevice* device, size_t limit)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    nabto_device_threads_mutex_lock(dev->eventMutex);
    nc_coap_server_limit_requests(&dev->core.coapServer, limit);
    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return nabto_device_error_core_to_api(NABTO_EC_OK);
}
