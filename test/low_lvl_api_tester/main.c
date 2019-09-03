
#include <platform/np_logging.h>
#include <core/nc_device.h>
#include <test_platform/test_platform.h>

#include <stdlib.h>

const char devicePrivateKey[] =
"-----BEGIN EC PARAMETERS-----\r\n"
"BggqhkjOPQMBBw==\r\n"
"-----END EC PARAMETERS-----\r\n"
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEII2ifv12piNfHQd0kx/8oA2u7MkmnQ+f8t/uvHQvr5wOoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEY1JranqmEwvsv2GK5OukVPhcjeOW+MRiLCpy7Xdpdcdc7he2nQgh\r\n"
"0+aTVTYvHZWacrSTZFQjXljtQBeuJR/Gsg==\r\n"
"-----END EC PRIVATE KEY-----\r\n";

const char devicePublicKey[] =
"-----BEGIN CERTIFICATE-----\r\n"
"MIIBaTCCARCgAwIBAgIJAOR5U6FNgvivMAoGCCqGSM49BAMCMBAxDjAMBgNVBAMM\r\n"
"BW5hYnRvMB4XDTE4MDgwNzA2MzgyN1oXDTQ4MDczMDA2MzgyN1owEDEOMAwGA1UE\r\n"
"AwwFbmFidG8wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARjUmtqeqYTC+y/YYrk\r\n"
"66RU+FyN45b4xGIsKnLtd2l1x1zuF7adCCHT5pNVNi8dlZpytJNkVCNeWO1AF64l\r\n"
"H8ayo1MwUTAdBgNVHQ4EFgQUjq36vzjxAQ7I8bMejCf1/m0eQ2YwHwYDVR0jBBgw\r\n"
"FoAUjq36vzjxAQ7I8bMejCf1/m0eQ2YwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO\r\n"
"PQQDAgNHADBEAiBF98p5zJ+98XRwIyvCJ0vcHy/eJM77fYGcg3J/aW+lIgIgMMu4\r\n"
"XndF4oYF4h6yysELSJfuiamVURjo+KcM1ixwAWo=\r\n"
"-----END CERTIFICATE-----\r\n";

const char* appVersion = "0.0.1";
const char* appName = "Weather_app";
const char* productId = "product";
const char* deviceId = "a";
//const char* hostname = "a.devices.dev.nabto.net";
const char* stunHost = "stun.nabto.net";


struct nabto_stream* stream;
uint8_t buffer[1500];

void stream_application_event_callback(nabto_stream_application_event_type eventType, void* data)
{
    NABTO_LOG_ERROR(0, "application event callback eventType: %s", nabto_stream_application_event_type_to_string(eventType));
    size_t readen = 0;
    size_t written = 0;
    nabto_stream_status status;
    status = nabto_stream_read_buffer(stream, buffer, 1500, &readen);
    if (status == NABTO_STREAM_STATUS_OK) {
        if (readen > 0) {
            nabto_stream_write_buffer(stream, buffer, readen, &written);
            NABTO_LOG_ERROR(0, "application event wrote %u bytes", written);
        }
    } else {
        status = nabto_stream_close(stream);
        if (status != NABTO_STREAM_STATUS_OK) {
            nabto_stream_release(stream);
        }
    }
}

void stream_listener(np_error_code ec, struct nc_stream_context* incStream, void* data)
{
    NABTO_LOG_INFO(0, "Test listener callback ");
    stream = &incStream->stream;
    nabto_stream_set_application_event_callback(stream, &stream_application_event_callback, data);
    nabto_stream_accept(stream);
}

int main() {
    np_error_code ec;

    struct test_platform tp;
    struct nc_device_context device;

    const char* hostname = "localhost";
    const char* deviceLbHost = getenv("DEVICE_LB_HOST");
    if (deviceLbHost) {
        hostname = deviceLbHost;
    }

    test_platform_init(&tp);

    nc_device_init(&device, &tp.pl);
    // start the core
    ec = nc_device_start(&device, appName, appVersion, productId, deviceId, hostname, stunHost,4242);
    if (ec != NABTO_EC_OK) {
        // fail
    }
    struct nc_stream_listener listener;
    nc_stream_manager_add_listener(&device.streamManager, &listener, 42, &stream_listener, NULL);

    test_platform_run(&tp);
    exit(0);
}
