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

#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/sha256.h"

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

// TODO: Take though api or something
const char* stunHost = "stun.nabto.net";

void* nabto_device_network_thread(void* data);
void* nabto_device_core_thread(void* data);
void nabto_device_init_platform(struct np_platform* pl);
void nabto_device_init_platform_modules(struct np_platform* pl, const char* devicePublicKey, const char* devicePrivateKey);
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
    // TODO: reintroduce this through the udp platform as to not leak buffers
    //nm_epoll_close(&dev->pl);
    if (dev->networkThread != NULL) {
        nabto_device_threads_join(dev->networkThread);
    }
    if (dev->coreThread != NULL) {
        nabto_device_threads_join(dev->coreThread);
    }
    free(dev);
}

/**
 * Self explanetory set functions
 */
NabtoDeviceError NABTO_DEVICE_API nabto_device_set_product_id(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (dev->productId != NULL) {
        free(dev->productId);
    }
    dev->productId = (char*)malloc(strlen(str)+1); // include trailing zero
    if (dev->productId == NULL) {
        return NABTO_DEVICE_EC_FAILED;
    }
    memcpy(dev->productId, str, strlen(str)+1); // include trailing zero
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_device_id(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (dev->deviceId != NULL) {
        free(dev->deviceId);
    }
    dev->deviceId = (char*)malloc(strlen(str)+1); // include trailing zero
    if (dev->deviceId == NULL) {
        return NABTO_DEVICE_EC_FAILED;
    }
    memcpy(dev->deviceId, str, strlen(str)+1); // include trailing zero
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;

}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_server_url(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (dev->serverUrl != NULL) {
        free(dev->serverUrl);
    }
    dev->serverUrl = (char*)malloc(strlen(str)+1); // include trailing zero
    if (dev->serverUrl == NULL) {
        return NABTO_DEVICE_EC_FAILED;
    }
    memcpy(dev->serverUrl, str, strlen(str)+1); // include trailing zero
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;

}

NabtoDeviceError NABTO_DEVICE_API nabto_device_set_private_key(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    if (dev->privateKey != NULL) {
        free(dev->privateKey);
    }
    dev->privateKey = (char*)malloc(strlen(str)+1); // include trailing zero
    if (dev->privateKey == NULL) {
        return NABTO_DEVICE_EC_FAILED;
    }
    memcpy(dev->privateKey, str, strlen(str)+1); // include trailing zero

    NabtoDeviceError status = nabto_device_create_crt_from_private_key(dev);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return status;

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
    dev->port = port;
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

NabtoDeviceError NABTO_DEVICE_API nabto_device_create_crt_from_private_key(struct nabto_device_context* dev)
{
    // 1. load key from pem
    // 2. create crt
    // 3. write crt to pem string.
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;

    int ret;

    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509write_crt_init(&crt);
    mbedtls_mpi_init(&serial);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        return NABTO_DEVICE_EC_FAILED;
    }

    ret = mbedtls_pk_parse_key( &key, (const unsigned char*)dev->privateKey, strlen(dev->privateKey)+1, NULL, 0 );
    if (ret != 0) {
        return NABTO_DEVICE_EC_FAILED;
    }

    // initialize crt
    mbedtls_x509write_crt_set_subject_key( &crt, &key );
    mbedtls_x509write_crt_set_issuer_key( &crt, &key );

    ret = mbedtls_mpi_read_string( &serial, 10, "1");
    if (ret != 0) {
        return NABTO_DEVICE_EC_FAILED;
    }

    mbedtls_x509write_crt_set_serial( &crt, &serial );

    ret = mbedtls_x509write_crt_set_subject_name( &crt, "CN=nabto" );
    if (ret != 0) {
        return NABTO_DEVICE_EC_FAILED;
    }

    ret = mbedtls_x509write_crt_set_issuer_name( &crt, "CN=nabto" );
    if (ret != 0) {
        return NABTO_DEVICE_EC_FAILED;
    }

    mbedtls_x509write_crt_set_version( &crt, 2 );
    mbedtls_x509write_crt_set_md_alg( &crt, MBEDTLS_MD_SHA256 );

    ret = mbedtls_x509write_crt_set_validity( &crt, "20010101000000", "20491231235959" );
    if (ret != 0) {
        return NABTO_DEVICE_EC_FAILED;
    }

    ret = mbedtls_x509write_crt_set_basic_constraints( &crt, 1, -1);
    if (ret != 0) {
        return NABTO_DEVICE_EC_FAILED;
    }

    {
        // write crt
        char buffer[1024];
        memset(buffer, 0, 1024);
        ret = mbedtls_x509write_crt_pem( &crt, (unsigned char*)buffer, 1024,
                                         mbedtls_ctr_drbg_random, &ctr_drbg );

        if (ret != 0) {
            return false;
        }
        int len = strlen(buffer);
        if (dev->publicKey != NULL) {
            free(dev->publicKey);
        }
        dev->publicKey = (char*)malloc(len+1); // include trailing zero
        if (dev->publicKey == NULL) {
            return NABTO_DEVICE_EC_FAILED;
        }
        memcpy(dev->publicKey, buffer, len+1); // include trailing zero
    }

    // TODO cleanup in case of error
    mbedtls_x509write_crt_free(&crt);
    mbedtls_mpi_free(&serial);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&key);
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
    nabto_device_init_platform_modules(&dev->pl, dev->publicKey, dev->privateKey);
    // start the core
    ec = nc_device_start(&dev->core, &dev->pl, dev->appName, dev->appVersion, dev->productId, dev->deviceId, dev->serverUrl, stunHost, dev->port);

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
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}


NabtoDeviceError NABTO_DEVICE_API nabto_device_get_device_fingerprint_hex(NabtoDevice* device, char* out)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    if (dev->publicKey == NULL) {
        return NABTO_DEVICE_EC_FAILED;
    }
    mbedtls_pk_context key;
    int ret;

    mbedtls_pk_init(&key);
    ret = mbedtls_pk_parse_key( &key, (const unsigned char*)dev->privateKey, strlen(dev->privateKey)+1, NULL, 0 );
    if (ret != 0) {
        return NABTO_DEVICE_EC_FAILED;
    }
    {
        // get fingerprint
        uint8_t buffer[256];
        uint8_t hash[32];
        // !!! The key is written to the end of the buffer
        int len = mbedtls_pk_write_pubkey_der( &key, buffer, sizeof(buffer));
        if (len <= 0) {
            return NABTO_DEVICE_EC_FAILED;
        }

        ret = mbedtls_sha256_ret(buffer+256 - len,  len, hash, false);
        if (ret != 0) {
            return NABTO_DEVICE_EC_FAILED;
        }

        sprintf(out, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                hash[0], hash[1], hash[2],  hash[3],  hash[4],  hash[5],  hash[6],  hash[7],
                hash[8], hash[9], hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]);

    }
    mbedtls_pk_free(&key);
    return NABTO_DEVICE_EC_OK;
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

/*******************************************
 * Streaming Api
 *******************************************/

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_listen(NabtoDevice* device, NabtoDeviceStream** stream)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_stream* str = (struct nabto_device_stream*)malloc(sizeof(struct nabto_device_stream));
    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    memset(str, 0, sizeof(struct nabto_device_stream));
    *stream = (NabtoDeviceStream*)str;
    str->listenFut = fut;
    str->dev = dev;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    nc_stream_manager_set_listener(&dev->core.streamManager, &nabto_device_stream_listener_callback, str);
    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return fut;
}

void NABTO_DEVICE_API nabto_device_stream_free(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    str->readyToFree = true;
    nabto_stream_release(str->stream);
    // TODO: resolve all futures
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
}



NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_accept(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)str->dev);
    if (str->acceptFut) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return fut;
    }
    str->acceptFut = fut;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    nabto_stream_set_application_event_callback(str->stream, &nabto_device_stream_application_event_callback, str);
    nabto_stream_accept(str->stream);
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return fut;
}

NabtoDeviceConnectionId NABTO_DEVICE_API nabto_device_stream_get_connection_id(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceConnectionId id;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);

    id = nc_device_get_connection_id_from_stream(&str->dev->core, str->stream);

    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return id;
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_read_all(NabtoDeviceStream* stream,
                                                void* buffer, size_t bufferLength,
                                                size_t* readLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)str->dev);
    if (str->readSomeFut || str->readAllFut) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return fut;
    }
    str->readAllFut = fut;
    str->readBuffer = buffer;
    str->readBufferLength = bufferLength;
    str->readLength = readLength;
    *str->readLength = 0;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    nabto_device_stream_do_read(str);
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return fut;
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_read_some(NabtoDeviceStream* stream,
                                                 void* buffer, size_t bufferLength,
                                                 size_t* readLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)str->dev);
    if (str->readSomeFut || str->readAllFut) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return fut;
    }
    str->readSomeFut = fut;
    str->readBuffer = buffer;
    str->readBufferLength = bufferLength;
    str->readLength = readLength;
    *str->readLength = 0;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    nabto_device_stream_do_read(str);
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return fut;
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_write(NabtoDeviceStream* stream,
                                             const void* buffer, size_t bufferLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)str->dev);
    if (str->writeFut) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return fut;
    }
    str->writeFut = fut;
    str->writeBuffer = buffer;
    str->writeBufferLength = bufferLength;
    nabto_device_threads_mutex_lock(str->dev->eventMutex);
    nabto_device_stream_do_write_all(str);
    nabto_device_threads_mutex_unlock(str->dev->eventMutex);
    return fut;
}

NabtoDeviceFuture* NABTO_DEVICE_API nabto_device_stream_close(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)str->dev);
    if (str->closeFut) {
        nabto_api_future_set_error_code(fut, nabto_device_error_core_to_api(NABTO_EC_OPERATION_IN_PROGRESS));
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return fut;
    }
    str->closeFut = fut;
    nabto_device_stream_handle_close(str);
    return fut;
}

/*******************************************
 * Streaming Api End
 *******************************************/

/*******************************************
 * COAP API Start
 *******************************************/

NabtoDeviceError NABTO_DEVICE_API
nabto_device_coap_add_resource(NabtoDevice* device,
                               NabtoDeviceCoapMethod method,
                               const char** pathSegments,
                               NabtoDeviceCoapResourceHandler handler,
                               void* userData)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_coap_resource* resource = (struct nabto_device_coap_resource*)malloc(sizeof(struct nabto_device_coap_resource));

    resource->dev = dev;
    resource->handler = handler;
    resource->userData = userData;

    nabto_device_threads_mutex_lock(dev->eventMutex);

    nabto_coap_server_add_resource(nc_coap_server_get_server(&dev->core.coap), nabto_device_coap_method_to_code(method), pathSegments, &nabto_device_coap_resource_handler, resource);

    nabto_device_threads_mutex_unlock(dev->eventMutex);

    return NABTO_DEVICE_EC_OK;
}

/* NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_notify_observers(NabtoDeviceCoapResource* resource) */
/* { */
/*     struct nabto_device_coap_resource* reso = (struct nabto_device_coap_resource*)resource; */
/*     nabto_device_threads_mutex_lock(reso->dev->eventMutex); */
/*     // TODO: implement observables */
/*     //nabto_coap_server_notify_observers(nc_coap_server_get_server(&reso->dev->core.coap), reso->res); */
/*     nabto_device_threads_mutex_unlock(reso->dev->eventMutex); */
/*     return NABTO_DEVICE_EC_OK; */
/* } */

NabtoDeviceCoapResponse* NABTO_DEVICE_API nabto_device_coap_create_response(NabtoDeviceCoapRequest* request)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;

    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    struct nabto_coap_server_response* resp = nabto_coap_server_create_response(req->req);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);

    struct nabto_device_coap_response* response = (struct nabto_device_coap_response*)malloc(sizeof(struct nabto_device_coap_response));
    response->resp = resp;
    response->dev = req->dev;
    response->req = req;
    return (NabtoDeviceCoapResponse*)response;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_response_set_code(NabtoDeviceCoapResponse* response, uint16_t code)
{
    struct nabto_device_coap_response* resp = (struct nabto_device_coap_response*)response;
    nabto_device_threads_mutex_lock(resp->dev->eventMutex);
    nabto_coap_server_response_set_code(resp->resp, nabto_coap_uint16_to_code(code));
    nabto_device_threads_mutex_unlock(resp->dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_response_set_payload(NabtoDeviceCoapResponse* response,
                                                        const void* data, size_t dataSize)
{
    struct nabto_device_coap_response* resp = (struct nabto_device_coap_response*)response;
    nabto_device_threads_mutex_lock(resp->dev->eventMutex);
    nabto_coap_server_response_set_payload(resp->resp, data, dataSize);
    nabto_device_threads_mutex_unlock(resp->dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_response_set_content_format(NabtoDeviceCoapResponse* response, uint16_t format)
{
    struct nabto_device_coap_response* resp = (struct nabto_device_coap_response*)response;
    nabto_device_threads_mutex_lock(resp->dev->eventMutex);
    nabto_coap_server_response_set_content_format(resp->resp, format);
    nabto_device_threads_mutex_unlock(resp->dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_response_ready(NabtoDeviceCoapResponse* response)
{
    struct nabto_device_coap_response* resp = (struct nabto_device_coap_response*)response;
    nabto_device_threads_mutex_lock(resp->dev->eventMutex);
    nabto_coap_server_response_ready(resp->resp);
    nabto_device_threads_mutex_unlock(resp->dev->eventMutex);
    free(resp->req);
    free(resp);
    return NABTO_DEVICE_EC_OK;
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_request_get_content_format(NabtoDeviceCoapRequest* request,
                                                              uint16_t* contentFormat)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    bool res = nabto_coap_server_request_get_content_format(req->req, contentFormat);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    if (res) {
        return NABTO_DEVICE_EC_OK;
    } else {
        return NABTO_DEVICE_EC_FAILED;
    }
}

NabtoDeviceError NABTO_DEVICE_API nabto_device_coap_request_get_payload(NabtoDeviceCoapRequest* request,
                                                       void** payload, size_t* payloadLength)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    nabto_coap_server_request_get_payload(req->req, payload, payloadLength);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    if(*payload == NULL) {
        return NABTO_DEVICE_EC_FAILED;
    } else {
        return NABTO_DEVICE_EC_OK;
    }
}

NabtoDeviceConnectionId nabto_device_coap_request_get_connection_id(NabtoDeviceCoapRequest* request)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    struct nc_client_connection* connection = (struct nc_client_connection*)nabto_coap_server_request_get_connection(req->req);
    NabtoDeviceConnectionId id;
    if (connection != NULL) {
        id = connection->connectionId;
    } else {
        id = 0;
    }
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    return id;
}

const char* NABTO_DEVICE_API nabto_device_coap_request_get_parameter(NabtoDeviceCoapRequest* request, const char* parameterName)
{
    struct nabto_device_coap_request* req = (struct nabto_device_coap_request*)request;
    const char* value;
    nabto_device_threads_mutex_lock(req->dev->eventMutex);
    value = nabto_coap_server_request_get_parameter(req->req, parameterName);
    nabto_device_threads_mutex_unlock(req->dev->eventMutex);
    return value;
}

/*******************************************
 * COAP API End
 *******************************************/

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
    if (ec != NABTO_EC_OK) {
        return NABTO_DEVICE_EC_FAILED;
    } else {
        return NABTO_DEVICE_EC_OK;
    }
}
