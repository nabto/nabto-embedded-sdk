#include <nabto/nabto_device_experimental.h>
#include "nabto_device_defines.h"

#include <stdlib.h>

NabtoDeviceError NABTO_DEVICE_API nabto_device_enable_mdns(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    nabto_device_threads_mutex_lock(dev->eventMutex);
    dev->enableMdns = true;
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
