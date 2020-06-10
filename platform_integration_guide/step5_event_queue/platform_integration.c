#include <api/nabto_device_platform.h>
#include <api/nabto_device_integration.h>

#include <modules/timestamp/unix/nm_unix_timestamp.h>

np_error_code nabto_device_platform_init(struct nabto_device_context* device, struct nabto_device_mutex* mutex)
{
    // Create a new instance of the unix timestamp module implementation.
    struct np_timestamp timestampImpl = nm_unix_ts_get_impl();

    // set the timestamp implementation in the device such that it can
    // be used by the device api.
    nabto_device_integration_set_timestamp_impl(device, &timestampImpl);

    return NABTO_EC_OK;
}
void nabto_device_platform_deinit(struct nabto_device_context* device)
{
    // TODO
}
void nabto_device_platform_stop_blocking(struct nabto_device_context* device)
{
    // TODO
}
