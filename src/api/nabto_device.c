#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include <api/nabto_device_defines.h>
#include <api/nabto_device_stream.h>
#include <api/nabto_api_future_queue.h>
#include <platform/np_error_code.h>

//TODO: only on linux
#include <modules/udp/epoll/nm_epoll.h>
#include <sys/time.h>

#include <platform/np_logging.h>
#include <platform/np_error_code.h>

#include <stdlib.h>

#define LOG NABTO_LOG_MODULE_API

// TODO: Take though api or something
const char* stunHost = "stun.nabto.net";

void* nabto_device_network_thread(void* data);
void* nabto_device_core_thread(void* data);
void nabto_device_init_platform(struct np_platform* pl);
void nabto_device_init_platform_modules(struct np_platform* pl, const char* devicePublicKey, const char* devicePrivateKey);
NabtoDeviceFuture* nabto_device_future_new(NabtoDevice* dev);

/**
 * Allocate new device
 */
NabtoDevice* nabto_device_new()
{
    struct nabto_device_context* dev = (struct nabto_device_context*)malloc(sizeof(struct nabto_device_context));
    memset(dev, 0, sizeof(struct nabto_device_context));
    nabto_device_init_platform(&dev->pl);
    dev->closing = false;
    return (NabtoDevice*)dev;
}

/**
 * free device when closed
 */
void nabto_device_free(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    dev->closing = true;
    nm_epoll_close(&dev->pl);
    pthread_join(dev->networkThread, NULL);
    pthread_join(dev->coreThread, NULL);
    free(dev);
}

/**
 * Self explanetory set functions
 */
NabtoDeviceError nabto_device_set_product_id(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    pthread_mutex_lock(&dev->eventMutex);
    if (dev->productId != NULL) {
        free(dev->productId);
    }
    dev->productId = (char*)malloc(strlen(str)+1); // include trailing zero
    if (dev->productId == NULL) {
        return NABTO_EC_FAILED;
    }
    memcpy(dev->productId, str, strlen(str)+1); // include trailing zero
    pthread_mutex_unlock(&dev->eventMutex);
    return NABTO_EC_OK;
}

NabtoDeviceError nabto_device_set_device_id(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    pthread_mutex_lock(&dev->eventMutex);
    if (dev->deviceId != NULL) {
        free(dev->deviceId);
    }
    dev->deviceId = (char*)malloc(strlen(str)+1); // include trailing zero
    if (dev->deviceId == NULL) {
        return NABTO_EC_FAILED;
    }
    memcpy(dev->deviceId, str, strlen(str)+1); // include trailing zero
    pthread_mutex_unlock(&dev->eventMutex);
    return NABTO_EC_OK;

}

NabtoDeviceError nabto_device_set_server_url(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    pthread_mutex_lock(&dev->eventMutex);
    if (dev->serverUrl != NULL) {
        free(dev->serverUrl);
    }
    dev->serverUrl = (char*)malloc(strlen(str)+1); // include trailing zero
    if (dev->serverUrl == NULL) {
        return NABTO_EC_FAILED;
    }
    memcpy(dev->serverUrl, str, strlen(str)+1); // include trailing zero
    pthread_mutex_unlock(&dev->eventMutex);
    return NABTO_EC_OK;

}

NabtoDeviceError nabto_device_set_public_key(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    pthread_mutex_lock(&dev->eventMutex);
    if (dev->publicKey != NULL) {
        free(dev->publicKey);
    }
    dev->publicKey = (char*)malloc(strlen(str)+1); // include trailing zero
    if (dev->publicKey == NULL) {
        return NABTO_EC_FAILED;
    }
    memcpy(dev->publicKey, str, strlen(str)+1); // include trailing zero
    pthread_mutex_unlock(&dev->eventMutex);
    return NABTO_EC_OK;

}

NabtoDeviceError nabto_device_set_private_key(NabtoDevice* device, const char* str)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    pthread_mutex_lock(&dev->eventMutex);
    if (dev->privateKey != NULL) {
        free(dev->privateKey);
    }
    dev->privateKey = (char*)malloc(strlen(str)+1); // include trailing zero
    if (dev->privateKey == NULL) {
        return NABTO_EC_FAILED;
    }
    memcpy(dev->privateKey, str, strlen(str)+1); // include trailing zero
    pthread_mutex_unlock(&dev->eventMutex);
    return NABTO_EC_OK;

}

NabtoDeviceError nabto_device_set_app_name(NabtoDevice* device, const char* name)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    if (strlen(name) > 32) {
        return NABTO_EC_FAILED;
    }
    pthread_mutex_lock(&dev->eventMutex);
    memcpy(dev->appName, name, strlen(name));
    pthread_mutex_unlock(&dev->eventMutex);
    return NABTO_EC_OK;
}

NabtoDeviceError nabto_device_set_app_version(NabtoDevice* device, const char* version)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    if (strlen(version) > 32) {
        return NABTO_EC_FAILED;
    }
    pthread_mutex_lock(&dev->eventMutex);
    memcpy(dev->appVersion, version, strlen(version));
    pthread_mutex_unlock(&dev->eventMutex);
    return NABTO_EC_OK;
}

NabtoDeviceError nabto_device_experimental_get_local_port(NabtoDevice* device, uint16_t* port)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    pthread_mutex_lock(&dev->eventMutex);
    *port = nc_udp_dispatch_get_local_port(&dev->core.udp);
    pthread_mutex_unlock(&dev->eventMutex);
    return NABTO_EC_OK;
}

/**
 * Starting the device
 */
NabtoDeviceError nabto_device_start(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    pthread_attr_t attr;
    np_error_code ec;
    pthread_mutex_lock(&dev->eventMutex);
    if (dev->publicKey == NULL || dev->privateKey == NULL || dev->serverUrl == NULL) {
        NABTO_LOG_ERROR(LOG, "Encryption key pair or server URL not set");
        return NABTO_EC_FAILED;
    }
    if (pthread_mutex_init(&dev->eventMutex, NULL) != 0) { 
        NABTO_LOG_ERROR(LOG, "mutex init has failed"); 
        return NABTO_EC_FAILED; 
    }
    if (pthread_cond_init(&dev->eventCond, NULL) != 0) {
        NABTO_LOG_ERROR(LOG, "condition init has failed");
        return NABTO_EC_FAILED;
    }
    if (pthread_attr_init(&attr) !=0) {
        NABTO_LOG_ERROR(LOG, "Failed to initialize pthread_attr");
        return NABTO_EC_FAILED;
    }
    if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
        NABTO_LOG_ERROR(LOG, "Failed to set detach state for pthread_attr");
        pthread_attr_destroy(&attr);
        return NABTO_EC_FAILED;
    }

    // Init platform
    nabto_device_init_platform_modules(&dev->pl, dev->publicKey, dev->privateKey);
    // start the core
    ec = nc_device_start(&dev->core, &dev->pl, dev->appName, dev->appVersion, dev->productId, dev->deviceId, dev->serverUrl, stunHost);

    if ( ec != NABTO_EC_OK ) {
        NABTO_LOG_ERROR(LOG, "Failed to start device core");
        pthread_attr_destroy(&attr);
        return ec;
    }

    if (pthread_create(&dev->coreThread, &attr, nabto_device_core_thread, dev) != 0) {
        NABTO_LOG_ERROR(LOG, "Failed to create pthread");
        pthread_attr_destroy(&attr);
        return NABTO_EC_FAILED;
    }
    if (pthread_create(&dev->networkThread, &attr, nabto_device_network_thread, dev) != 0) {
        NABTO_LOG_ERROR(LOG, "Failed to create pthread");
        pthread_attr_destroy(&attr);
        return NABTO_EC_FAILED;
    }
    pthread_attr_destroy(&attr);
    pthread_mutex_unlock(&dev->eventMutex);
     
}


/**
 * Closing the device
 */
void nabto_device_close_cb(const np_error_code ec, void* data)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)data;
    nabto_api_future_set_error_code(dev->closeFut, ec);
    nabto_api_future_queue_post(&dev->queueHead, dev->closeFut);
}

NabtoDeviceFuture* nabto_device_close(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    pthread_mutex_lock(&dev->eventMutex);
    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    dev->closeFut = fut;
    nc_device_close(&dev->core, &nabto_device_close_cb, dev);
    pthread_mutex_unlock(&dev->eventMutex);
    return fut;
}


/*******************************************
 * Streaming Api
 *******************************************/

NabtoDeviceFuture* nabto_device_stream_listen(NabtoDevice* device, NabtoDeviceStream** stream)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    struct nabto_device_stream* str = (struct nabto_device_stream*)malloc(sizeof(struct nabto_device_stream));
    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    memset(str, 0, sizeof(struct nabto_device_stream));
    *stream = (NabtoDeviceStream*)str;
    str->listenFut = fut;
    str->dev = dev;
    pthread_mutex_lock(&dev->eventMutex);
    nc_stream_manager_set_listener(&dev->core.streamManager, &nabto_device_stream_listener_callback, str);
    pthread_mutex_unlock(&dev->eventMutex);
    return fut;
}

void nabto_device_stream_free(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    pthread_mutex_lock(&str->dev->eventMutex);
    nabto_stream_destroy(str->stream);
    // TODO: resolve all futures
    pthread_mutex_unlock(&str->dev->eventMutex);
    free(str);
}

NabtoDeviceFuture* nabto_device_stream_accept(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)str->dev);
    if (str->acceptFut) {
        nabto_api_future_set_error_code(fut, NABTO_EC_OPERATION_IN_PROGRESS);
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return fut;
    }
    str->acceptFut = fut;
    pthread_mutex_lock(&str->dev->eventMutex);
    // TODO: Set start sequence number ?
    nabto_stream_set_application_event_callback(str->stream, &nabto_device_stream_application_event_callback, str);
    nabto_stream_accept(str->stream);
    pthread_mutex_unlock(&str->dev->eventMutex);
    return fut;
}

NabtoDeviceFuture* nabto_device_stream_read_all(NabtoDeviceStream* stream,
                                                void* buffer, size_t bufferLength,
                                                size_t* readLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)str->dev);
    if (str->readSomeFut || str->readAllFut) {
        nabto_api_future_set_error_code(fut, NABTO_EC_OPERATION_IN_PROGRESS);
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return fut;
    }
    str->readAllFut = fut;
    str->readBuffer = buffer;
    str->readBufferLength = bufferLength;
    str->readLength = readLength;
    *str->readLength = 0;
    pthread_mutex_lock(&str->dev->eventMutex);
    nabto_device_stream_do_read(str);
    pthread_mutex_unlock(&str->dev->eventMutex);
    return fut;
}

NabtoDeviceFuture* nabto_device_stream_read_some(NabtoDeviceStream* stream,
                                                 void* buffer, size_t bufferLength,
                                                 size_t* readLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)str->dev);
    if (str->readSomeFut || str->readAllFut) {
        nabto_api_future_set_error_code(fut, NABTO_EC_OPERATION_IN_PROGRESS);
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return fut;
    }
    str->readSomeFut = fut;
    str->readBuffer = buffer;
    str->readBufferLength = bufferLength;
    str->readLength = readLength;    
    *str->readLength = 0;
    pthread_mutex_lock(&str->dev->eventMutex);
    nabto_device_stream_do_read(str);
    pthread_mutex_unlock(&str->dev->eventMutex);
    return fut;
}

NabtoDeviceFuture* nabto_device_stream_write(NabtoDeviceStream* stream,
                                             const void* buffer, size_t bufferLength)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)str->dev);
    if (str->writeFut) {
        nabto_api_future_set_error_code(fut, NABTO_EC_OPERATION_IN_PROGRESS);
        nabto_api_future_queue_post(&str->dev->queueHead, fut);
        return fut;
    }
    str->writeFut = fut;
    str->writeBuffer = buffer;
    str->writeBufferLength = bufferLength;
    pthread_mutex_lock(&str->dev->eventMutex);
    nabto_device_stream_do_write_all(str);
    pthread_mutex_unlock(&str->dev->eventMutex);
    return fut;
}

NabtoDeviceFuture* nabto_device_stream_close(NabtoDeviceStream* stream)
{
    struct nabto_device_stream* str = (struct nabto_device_stream*)stream;
    NabtoDeviceFuture* fut = nabto_device_future_new((NabtoDevice*)str->dev);
    if (str->closeFut) {
        nabto_api_future_set_error_code(fut, NABTO_EC_OPERATION_IN_PROGRESS);
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

/*
 * Thread running the network
 */
void* nabto_device_network_thread(void* data)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)data;
    int nfds;
    while(true) {
        nfds = nm_epoll_wait(0);
        pthread_mutex_lock(&dev->eventMutex);
        if (nfds > 0) {
            nm_epoll_read(nfds);
        }
        pthread_cond_signal(&dev->eventCond);
        if (dev->closing) {
            pthread_mutex_unlock(&dev->eventMutex);
            return NULL;
        }
        pthread_mutex_unlock(&dev->eventMutex);
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
        struct timespec ts;
        struct timeval tp;
        NABTO_LOG_TRACE(LOG, "start of while");

        pthread_mutex_lock(&dev->eventMutex);
        np_event_queue_execute_all(&dev->pl);
        pthread_mutex_unlock(&dev->eventMutex);

        NABTO_LOG_TRACE(LOG, "dev->queueHead %u", dev->queueHead);
        nabto_api_future_queue_execute_all(&dev->queueHead);
        NABTO_LOG_TRACE(LOG, "dev->queueHead %u", dev->queueHead);
        if (dev->closing) {
            return NULL;
        }

        pthread_mutex_lock(&dev->eventMutex);
        if (np_event_queue_has_timed_event(&dev->pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&dev->pl);
            NABTO_LOG_TRACE(LOG, "Found timed events, waits %u ms for signals", ms);
            int rc = gettimeofday(&tp, NULL);
            long future_us = tp.tv_usec+ms*1000;
            ts.tv_nsec = (future_us % 1000000) * 1000;
            ts.tv_sec = tp.tv_sec + future_us / 1000000;

            pthread_cond_timedwait(&dev->eventCond, &dev->eventMutex, &ts);
        } else {

            NABTO_LOG_TRACE(LOG, "no timed events, waits for signals forever");
            pthread_cond_wait(&dev->eventCond, &dev->eventMutex);
        }
        pthread_mutex_unlock(&dev->eventMutex);
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
