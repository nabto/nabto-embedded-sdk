#include <nabto/nabto_device.h>
#include <stdlib.h>

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

#include <platform/np_logging.h>

struct streamContext {
    NabtoDeviceStream* stream;
    uint8_t buf[1500];
    size_t readen;
};

void readSomeCallback(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data);
void closeStream(struct streamContext* strCtx);
void closeCallback(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data);

void writeCallback(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data)
{
    struct streamContext* strCtx = (struct streamContext*)data;
    nabto_device_future_free(fut);
    NABTO_LOG_INFO(0, "Stream write callback invoked");
    if (err == NABTO_DEVICE_EC_FAILED) {
        NABTO_LOG_INFO(0, "stream closed or aborted");
        closeStream(strCtx);
        return;
    }
    memset(strCtx->buf, 0, 1500);
    fut = nabto_device_stream_read_some(strCtx->stream, strCtx->buf, 1500, &strCtx->readen);
    nabto_device_future_set_callback(fut, &readSomeCallback, strCtx);
}

void readSomeCallback(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data)
{
    struct streamContext* strCtx = (struct streamContext*)data;
    nabto_device_future_free(fut);
    if (err == NABTO_DEVICE_EC_FAILED) {
        NABTO_LOG_INFO(0, "stream closed or aborted");
        closeStream(strCtx);
        return;
    }
    NABTO_LOG_INFO(0, "read %u bytes into buf:", strCtx->readen);
    NABTO_LOG_BUF(0, strCtx->buf, strCtx->readen);

    fut = nabto_device_stream_write(strCtx->stream, strCtx->buf, strCtx->readen);
    nabto_device_future_set_callback(fut, &writeCallback, strCtx);
}

void closeStream(struct streamContext* strCtx)
{
    NabtoDeviceFuture* fut = nabto_device_stream_close(strCtx->stream);
    nabto_device_future_set_callback(fut, &closeCallback, strCtx);
}

void closeCallback(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data)
{
    struct streamContext* strCtx = (struct streamContext*)data;
    nabto_device_future_free(fut);
    nabto_device_stream_free(strCtx->stream);
    free(strCtx);
}

void acceptCallback(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data)
{
    struct streamContext* strCtx = (struct streamContext*)data;
    nabto_device_future_free(fut);
    fut = nabto_device_stream_read_some(strCtx->stream, strCtx->buf, 1500, &strCtx->readen);
    nabto_device_future_set_callback(fut, &readSomeCallback, strCtx);
}

void acceptStream(struct streamContext* strCtx) {
    NabtoDeviceFuture* fut = nabto_device_stream_accept(strCtx->stream);
    nabto_device_future_set_callback(fut, &acceptCallback, strCtx);
}

int main(void)
{
    const char* serverHostname = "a.devices.dev.nabto.net";
    NabtoDeviceStream* stream;
    NabtoDevice* dev = nabto_device_new();

    char* deviceLbEnv = getenv("DEVICE_LB_HOST");
    if (deviceLbEnv) {
        serverHostname = deviceLbEnv;
    }

    nabto_device_set_private_key(dev, (const char*)devicePrivateKey);
    nabto_device_set_server_url(dev, serverHostname);
    nabto_device_set_std_out_log_callback();
    nabto_device_start(dev);

    while (true) {
        NabtoDeviceFuture* fut = nabto_device_stream_listen(dev, &stream);
        nabto_device_future_wait(fut);
        nabto_device_future_free(fut);
        struct streamContext* strCtx = malloc(sizeof(struct streamContext));
        strCtx->stream = stream;
        acceptStream(strCtx);

    }
}
