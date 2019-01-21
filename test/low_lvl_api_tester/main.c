
#include <platform/np_logging.h>
#include <core/nc_device.h>

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

struct nc_device_context device;
struct np_platform pl;
struct nabto_stream* stream;
uint8_t buffer[1500];

void nabto_device_init_platform(struct np_platform* pl);
void nabto_device_init_platform_modules(struct np_platform* pl,
                                        const char* devicePublicKey,
                                        const char* devicePrivateKey);

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

void stream_listener(struct nabto_stream* incStream, void* data)
{
    NABTO_LOG_INFO(0, "Test listener callback ");
    stream = incStream;
    nabto_stream_set_application_event_callback(stream, &stream_application_event_callback, data);
    nabto_stream_accept(stream);
}

int main() {
    np_error_code ec;
    int nfds;
    const char* hostname = "localhost";
    const char* deviceLbHost = getenv("DEVICE_LB_HOST");
    if (deviceLbHost) {
        hostname = deviceLbHost;
    }

    nabto_device_init_platform(&pl);
    nabto_device_init_platform_modules(&pl, devicePublicKey, devicePrivateKey);
    // start the core
    ec = nc_device_start(&device, &pl, appName, appVersion, productId, deviceId, hostname, stunHost);
    if (ec != NABTO_EC_OK) {
        // fail
    }
    nc_stream_manager_set_listener(&device.streamManager, &stream_listener, NULL);
    
    while (true) {
        np_event_queue_execute_all(&pl);
        if (np_event_queue_has_timed_event(&pl)) {
            uint32_t ms = np_event_queue_next_timed_event_occurance(&pl);
            nfds = pl.udp.timed_wait(ms);
        } else {
            nfds = pl.udp.inf_wait();
        }
        pl.udp.read(nfds);
    }
    
    exit(0);
   
}
