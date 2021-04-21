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

#include <platform/np_logging.h>
#include <platform/np_error_code.h>
#include <core/nc_version.h>
#include <core/nc_client_connection.h>

#include <modules/mbedtls/nm_mbedtls_util.h>
#include <modules/mbedtls/nm_mbedtls_cli.h>
#include <modules/mbedtls/nm_mbedtls_srv.h>
#include <modules/mbedtls/nm_mbedtls_random.h>

#include <modules/communication_buffer/nm_communication_buffer.h>

//#include "nabto_device_event_queue.h"

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

static const char* defaultServerUrlSuffix = ".devices.nabto.net";

void nabto_device_free_threads(struct nabto_device_context* dev);
void nabto_device_do_stop(struct nabto_device_context* dev);

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
    struct nabto_device_context* dev = calloc(1, sizeof(struct nabto_device_context));
    np_error_code ec;
    if (dev == NULL) {
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
    nm_mbedtls_cli_init(pl);
    nm_mbedtls_srv_init(pl);
    nm_mbedtls_random_init(pl);

    ec = nabto_device_platform_init(dev, dev->eventMutex);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to initialize platform modules");
        return NULL;
    }

    nabto_device_authorization_init_module(dev);

    ec = nc_device_init(&dev->core, &dev->pl);
    if (ec != NABTO_EC_OK) {
        nabto_device_new_resolve_failure(dev);
        return NULL;
    }

    ec = nm_tcp_tunnels_init(&dev->tcpTunnels, &dev->core);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to start tcp tunnelling module");
        nabto_device_new_resolve_failure(dev);
        return NULL;
    }

    nn_llist_init(&dev->listeners);

    ec = nabto_device_future_queue_init(&dev->futureQueue);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to start future_queue");
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

    nm_tcp_tunnels_deinit(&dev->tcpTunnels);
    nc_device_stop(&dev->core);

    dev->closing = true;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    nabto_device_do_stop(dev);
}

void nabto_device_do_stop(struct nabto_device_context* dev)
{
    nabto_device_platform_stop_blocking(dev);
    nabto_device_future_queue_stop(&dev->futureQueue);
}

/**
 * free device when closed
 */
void NABTO_DEVICE_API nabto_device_free(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    nabto_device_stop(device);

    //nabto_device_event_queue_stop(&dev->pl);

    nc_device_deinit(&dev->core);


    nabto_device_platform_deinit(dev);
    nm_mbedtls_random_deinit(&dev->pl);
    nabto_device_future_queue_deinit(&dev->futureQueue);
    nabto_device_free_threads(dev);

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
    free(dev->privateKey);

    dev->privateKey = strdup(str);
    if (dev->privateKey == NULL) {
        ec = NABTO_EC_OUT_OF_MEMORY;
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
    } else {
        *port = p;
    }
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
    } else {
        *port = p;
    }
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_enable_mdns(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nc_device_enable_mdns(&dev->core);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_mdns_add_subtype(NabtoDevice* device, const char* subtype)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nc_device_mdns_add_subtype(&dev->core, subtype);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_mdns_add_txt_item(NabtoDevice* device, const char* key, const char* value)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    np_error_code ec = NABTO_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    ec = nc_device_mdns_add_txt_item(&dev->core, key, value);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return nabto_device_error_core_to_api(ec);
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



    dev->startFut = fut;

    if (dev->publicKey == NULL || dev->privateKey == NULL) {
        NABTO_LOG_ERROR(LOG, "Encryption key pair not set");
        nabto_device_future_resolve(fut, NABTO_EC_INVALID_STATE);
    } else {

        // Init platform
        nc_device_set_keys(&dev->core, (const unsigned char*)dev->publicKey, strlen(dev->publicKey), (const unsigned char*)dev->privateKey, strlen(dev->privateKey));

        // start the core
        np_error_code ec = nc_device_start(&dev->core, defaultServerUrlSuffix, &nabto_device_start_cb, dev);
        if (ec != NABTO_EC_OK) {
            nabto_device_future_resolve(fut, ec);
        }
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
}

static char* toHex(uint8_t* data, size_t dataLength)
{
    size_t outputLength = dataLength*2 + 1;
    char* output = (char*)malloc(outputLength);
    if (output == NULL) {
        return output;
    }
    memset(output,0,outputLength);
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
    }
    uint8_t hash[32];
    ec = nm_dtls_get_fingerprint_from_private_key(dev->privateKey, hash);
    if (ec == NABTO_EC_OK) {
        *fingerprint = toHex(hash, 32);
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
    }
    uint8_t hash[32];
    ec = nm_dtls_get_fingerprint_from_private_key(dev->privateKey, hash);
    if (ec == NABTO_EC_OK) {
        *fingerprint = toHex(hash, 16);
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

    struct nc_client_connection* connection = nc_device_connection_from_ref(&dev->core, connectionRef);

    if (connection == NULL || nc_client_connection_get_client_fingerprint(connection, clientFingerprint) != NABTO_EC_OK) {
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

    struct nc_client_connection* connection = nc_device_connection_from_ref(&dev->core, connectionRef);

    if (connection == NULL || nc_client_connection_get_client_fingerprint(connection, clientFingerprint) != NABTO_EC_OK) {
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
    struct nc_client_connection* connection = nc_device_connection_from_ref(&dev->core, ref);
    if (connection != NULL) {
        local = nc_client_connection_is_local(connection);
    }
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return local;
}

/**
 * Closing the device
 */
void nabto_device_close_cb(const np_error_code ec, void* data)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)data;
    nabto_device_future_resolve(dev->closeFut, nabto_device_error_core_to_api(ec));
    nc_device_events_listener_notify(NC_DEVICE_EVENT_CLOSED, &dev->core);
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
    nabto_device_logging_set_callback(cb, data);
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
    nabto_device_logging_set_level(l);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_log_std_out_callback(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_logging_set_callback(&nabto_device_logging_std_out_callback, &dev->pl);
    return NABTO_DEVICE_EC_OK;
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
        *serverConnectToken = strdup(output);
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
    dev->core.clientConnect.maxConcurrentConnections = limit;
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
