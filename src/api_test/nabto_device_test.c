#include <nabto/nabto_device_config.h>
#include <nabto/nabto_device_test.h>

#include <api/nabto_device_defines.h>
#include <api/nabto_device_threads.h>
#include <api/nabto_device_platform.h>
#include <api/nabto_device_future_queue.h>
#include <api/nabto_device_logging.h>


#ifdef NABTO_DEVICE_MBEDTLS
#include <modules/mbedtls/nm_mbedtls_util.h>
#include <modules/mbedtls/nm_mbedtls_cli.h>
#include <modules/mbedtls/nm_mbedtls_random.h>
#include <modules/mbedtls/nm_mbedtls_spake2.h>
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
#include <modules/mbedtls/nm_mbedtls_srv.h>
#endif
#endif
#ifdef NABTO_DEVICE_WOLFSSL
#include <modules/wolfssl/nm_wolfssl_util.h>
#include <modules/wolfssl/nm_wolfssl_cli.h>
#include <modules/wolfssl/nm_wolfssl_random.h>
#include <modules/wolfssl/nm_wolfssl_spake2.h>
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
#include <modules/wolfssl/nm_wolfssl_srv.h>
#endif
#endif

#include <modules/communication_buffer/nm_communication_buffer.h>

#include <platform/np_logging.h>
#include <platform/np_allocator.h>

#define LOG NABTO_LOG_MODULE_TEST

NabtoDevice* NABTO_DEVICE_API nabto_device_test_new()
{

    struct nabto_device_context* dev = np_calloc(1, sizeof(struct nabto_device_context));
    np_error_code ec = NABTO_EC_FAILED;
    if (dev == NULL) {
        return NULL;
    }

    dev->closing = false;
    dev->eventMutex = nabto_device_threads_create_mutex();

    if (dev->eventMutex == NULL) {
        NABTO_LOG_ERROR(LOG, "mutex init has failed");
        return NULL;
    }

    nabto_device_logging_init();

    struct np_platform* pl = &dev->pl;
    nm_communication_buffer_init(pl);

#if defined(NABTO_DEVICE_MBEDTLS)
    ec = nm_mbedtls_cli_init(pl);
    if (ec != NABTO_EC_OK) {
        return NULL;
    }

    bool status = nm_mbedtls_random_init(pl);
    if (!status) {
        return NULL;
    }

#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
    ec = nm_mbedtls_spake2_init(pl);
    if (ec != NABTO_EC_OK) {
        return NULL;
    }
#endif
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
    ec = nm_mbedtls_srv_init(pl);
    if (ec != NABTO_EC_OK) {
        return NULL;
    }
#endif

#elif defined(NABTO_DEVICE_WOLFSSL)
    ec = nm_wolfssl_cli_init(pl);
    if (ec != NABTO_EC_OK) {
        return NULL;
    }
    ec = nm_wolfssl_random_init(pl);
    if (ec != NABTO_EC_OK) {
        return NULL;
    }
#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
    ec = nm_wolfssl_spake2_init(pl);
    if (ec != NABTO_EC_OK) {
        return NULL;
    }
#endif
#ifndef NABTO_DEVICE_DTLS_CLIENT_ONLY
    ec = nm_wolfssl_srv_init(pl);
    if (ec != NABTO_EC_OK) {
        return NULL;
    }
#endif
#else
#error Missing DTLS implementation
#endif

    ec = nabto_device_platform_init(dev, dev->eventMutex);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to initialize platform modules");
        return NULL;
    }

#if defined(NABTO_DEVICE_FUTURE_QUEUE)

    ec = nabto_device_future_queue_init(&dev->futureQueue);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to start future_queue");
        return NULL;
    }
#endif

    return (NabtoDevice*)dev;
}

void NABTO_DEVICE_API nabto_device_test_stop(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    if (dev->closing) {
        return;
    }
    dev->closing = true;
    nabto_device_threads_mutex_unlock(dev->eventMutex);
#if defined(NABTO_DEVICE_FUTURE_QUEUE)
    nabto_device_future_queue_stop(&dev->futureQueue);
#endif
    nabto_device_platform_stop_blocking(dev);
}

void NABTO_DEVICE_API nabto_device_test_free(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    nabto_device_test_stop(device);

    nabto_device_platform_deinit(dev);
#ifdef NABTO_DEVICE_MBEDTLS
    nm_mbedtls_random_deinit(&dev->pl);
#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
    nm_mbedtls_spake2_deinit(&dev->pl);
#endif
#endif
#ifdef NABTO_DEVICE_WOLFSSL
    nm_wolfssl_random_deinit(&dev->pl);
#if defined(NABTO_DEVICE_PASSWORD_AUTHENTICATION)
    nm_wolfssl_spake2_deinit(&dev->pl);
#endif
#endif

#if defined(NABTO_DEVICE_FUTURE_QUEUE)
    nabto_device_future_queue_deinit(&dev->futureQueue);
#endif

    np_free(dev->certificate);
    np_free(dev->privateKey);

    if (dev->eventMutex) {
        nabto_device_threads_free_mutex(dev->eventMutex);
        dev->eventMutex = NULL;
    }

    np_free(dev);


}
