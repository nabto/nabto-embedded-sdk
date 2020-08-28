#include <nabto/nabto_device_test.h>
#include <api/nabto_device_defines.h>

#include <platform/np_mdns_wrapper.h>

void NABTO_DEVICE_API
nabto_device_test_mdns_publish_service(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;

    np_mdns_publish_service(&dev->pl.mdns, 4242, "pr-12345678-de-abcdefgh", NULL, NULL);
}
