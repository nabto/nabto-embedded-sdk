#include <nabto/nabto_device_test.h>

#include <api/nabto_device_defines.h>
#include <api/nabto_device_threads.h>
#include <api/nabto_device_platform.h>
#include <api/nabto_device_future_queue.h>
#include <api/nabto_device_logging.h>

#include <modules/mbedtls/nm_mbedtls_util.h>
#include <modules/mbedtls/nm_mbedtls_cli.h>
#include <modules/mbedtls/nm_mbedtls_srv.h>
#include <modules/mbedtls/nm_mbedtls_random.h>
#include <modules/communication_buffer/nm_communication_buffer.h>

#include <platform/np_logging.h>
#include <platform/np_allocator.h>

#define LOG NABTO_LOG_MODULE_TEST

NabtoDevice* NABTO_DEVICE_API nabto_device_test_new()
{
    struct nabto_device_context* dev = np_calloc(1, sizeof(struct nabto_device_context));
    np_error_code ec;
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
    nm_mbedtls_cli_init(pl);
    nm_mbedtls_srv_init(pl);
    nm_mbedtls_random_init(pl);

    ec = nabto_device_platform_init(dev, dev->eventMutex);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to initialize platform modules");
        return NULL;
    }

    ec = nabto_device_future_queue_init(&dev->futureQueue);
    if (ec != NABTO_EC_OK) {
        NABTO_LOG_ERROR(LOG, "Failed to start future_queue");
        return NULL;
    }

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

    nabto_device_future_queue_stop(&dev->futureQueue);
    nabto_device_platform_stop_blocking(dev);
}

void NABTO_DEVICE_API nabto_device_test_free(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    nabto_device_test_stop(device);

    nabto_device_platform_deinit(dev);
    nm_mbedtls_random_deinit(&dev->pl);
    nabto_device_future_queue_deinit(&dev->futureQueue);

    np_free(dev->publicKey);
    np_free(dev->privateKey);

    if (dev->eventMutex) {
        nabto_device_threads_free_mutex(dev->eventMutex);
        dev->eventMutex = NULL;
    }

    np_free(dev);


}
