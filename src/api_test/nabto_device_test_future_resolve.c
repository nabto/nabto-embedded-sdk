#include <nabto/nabto_device_test.h>

#include <api/nabto_device_future.h>

void NABTO_DEVICE_API
nabto_device_test_future_resolve(NabtoDevice* device, NabtoDeviceFuture* future)
{
    (void)device;
    struct nabto_device_future* fut = (struct nabto_device_future*)future;
    nabto_device_future_reset(fut);
    nabto_device_future_resolve(fut, NABTO_DEVICE_EC_OK);
}
