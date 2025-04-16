#include <nabto/nabto_device_test.h>

#include <platform/np_ip_address.h>
#include <platform/np_local_ip_wrapper.h>
#include <platform/np_logging.h>
#include <api/nabto_device_defines.h>

#define LOG NABTO_LOG_MODULE_TEST

void NABTO_DEVICE_API nabto_device_test_local_ip(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    size_t localIpsSize = 0;
    struct np_ip_address ips[4];
    localIpsSize = np_local_ip_get_local_ips(&dev->pl.localIp, ips, 4);
    NABTO_LOG_INFO(LOG, "Found %d local ips", localIpsSize);
    for (size_t i = 0; i < localIpsSize; i++) {
        NABTO_LOG_INFO(LOG, "Local ip %d: %s", i, np_ip_address_to_string(&ips[i]));
    }
}
