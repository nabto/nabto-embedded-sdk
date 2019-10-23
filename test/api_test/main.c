#include <nabto/nabto_device.h>

const unsigned char devicePrivateKey[] =
"-----BEGIN EC PARAMETERS-----\r\n"
"BggqhkjOPQMBBw==\r\n"
"-----END EC PARAMETERS-----\r\n"
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEII2ifv12piNfHQd0kx/8oA2u7MkmnQ+f8t/uvHQvr5wOoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEY1JranqmEwvsv2GK5OukVPhcjeOW+MRiLCpy7Xdpdcdc7he2nQgh\r\n"
"0+aTVTYvHZWacrSTZFQjXljtQBeuJR/Gsg==\r\n"
"-----END EC PRIVATE KEY-----\r\n";

const unsigned char devicePublicKey[] =
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

const char* hostname = "localhost";
//const char* hostname = "a.devices.dev.nabto.net";
const char* buf = "helloworld";

#include <platform/np_logging.h>

void handler(NabtoDeviceCoapRequest* req, void* data)
{
    NABTO_LOG_TRACE(0, "Handler called!!");
    NabtoDeviceCoapResponse* resp = nabto_device_coap_create_response(req);
    nabto_device_coap_response_set_code(resp, 205);
    nabto_device_coap_response_set_payload(resp, buf, strlen(buf));
    nabto_device_coap_response_ready(resp);
}

int main()
{
    NabtoDevice* dev = nabto_device_new();
    NabtoDeviceStream* stream;
    uint8_t buf[1500];
    size_t readen;
    nabto_device_log_set_std_out_callback(dev);
    nabto_device_set_private_key(dev, (const char*)devicePrivateKey);
    nabto_device_set_server_url(dev, hostname);
    nabto_device_start(dev);

    NabtoDeviceListener* hwListener;
    nabto_device_coap_listener_new(dev, NABTO_DEVICE_COAP_GET, (const char*[]){"helloworld", NULL}, &hwListener);

    NabtoDeviceFuture* fut;
    NabtoDeviceListener* listener = nabto_device_stream_listener_new(dev, 42);
    if (listener == NULL) {
        NABTO_LOG_ERROR(0, "Failed to create stream listener");
        return 1;
    }
    NabtoDeviceError err = nabto_device_listener_new_stream(listener, &fut, &stream);
    if (err != NABTO_DEVICE_EC_OK) {
        NABTO_LOG_ERROR(0, "Failed to listen to listener: %d", err);
        return 1;
    }
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);

    fut = nabto_device_stream_accept(stream);
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);

    fut = nabto_device_stream_read_some(stream, buf, 1500, &readen);
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
    NABTO_LOG_INFO(0, "read %u bytes into buf:", readen);
    NABTO_LOG_BUF(0, buf, readen);

    fut = nabto_device_stream_write(stream, buf, readen);
    if (fut == NULL) {
        NABTO_LOG_ERROR(0, "Write returned NULL future");
    } else {
        nabto_device_future_wait(fut);
        nabto_device_future_free(fut);
    }

    fut = nabto_device_stream_close(stream);
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);

    fut = nabto_device_close(dev);
    nabto_device_future_wait(fut);
    if (nabto_device_future_error_code(fut) == NABTO_DEVICE_EC_OK) {
        NABTO_LOG_INFO(0, "Close OK");
    } else {
        NABTO_LOG_INFO(0, "Close FAILED");
    }
    nabto_device_future_free(fut);
    nabto_device_free(dev);
}
