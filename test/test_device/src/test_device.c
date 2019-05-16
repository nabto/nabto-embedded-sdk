
#include <nabto/nabto_device.h>

#include <gopt/gopt.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_KEY_PEM_SIZE 1024
#define MAX_CRT_PEM_SIZE 1024

struct config {
    const char* productId;
    const char* deviceId;
    const char* keyFile;
    const char* hostname;
    char keyPemBuffer[MAX_KEY_PEM_SIZE];
};

static struct config config;

struct streamContext {
    NabtoDeviceStream* stream;
    uint8_t buffer[1500];
    size_t read;
};

#ifdef _WIN32
#define NEWLINE "\r\n"
#else
#define NEWLINE "\n"
#endif

void stream_read_callback(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data);

void print_help(const char* message)
{
    if (message) {
        printf("%s", message);
        printf(NEWLINE);
    }
    printf("test_device version %s" NEWLINE, nabto_device_version());
    printf(" USAGE test_device -p <productId> -d <deviceId> -k <keyfile> --hostname <hostname>" NEWLINE);
    printf(" Create a new keypair using `openssl ecparam -genkey -name prime256v1 -out <keyfile>`" NEWLINE);
}

bool parse_args(int argc, const char** argv)
{
    const char* productId;
    const char* deviceId;
    const char* keyFile;
    const char* hostname;

    const char* helpLong[] = { "help", 0 };
    const char* productLong[] = { "product", 0 };
    const char* deviceLong[] = { "device", 0 };
    const char* keyFileLong[] = { "keyfile", 0 };
    const char* hostnameLong[] = { "hostname", 0 };

    const struct { int key; int format; const char* shortName; const char*const* longNames; } opts[] = {
        { 1, GOPT_NOARG, "h", helpLong },
        { 2, GOPT_ARG, "p", productLong },
        { 3, GOPT_ARG, "d", deviceLong },
        { 4, GOPT_ARG, "k", keyFileLong },
        { 5, GOPT_ARG, "", hostnameLong },
        {0,0,0,0}
    };

    void *options = gopt_sort( & argc, argv, opts);
    if( gopt( options, 1)) {
        print_help(NULL);
        return false;
    }

    if (gopt_arg(options, 2, &productId)) {
        config.productId = productId;
    } else {
        print_help("Missing product id");
        return false;
    }

    if (gopt_arg(options, 3, &deviceId)) {
        config.deviceId = deviceId;
    } else {
        print_help("Missing device id");
        return false;
    }

    if (gopt_arg(options, 4, &keyFile)) {
        config.keyFile = keyFile;
    } else {
        print_help("Missing key filename");
        return false;
    }

    if (gopt_arg(options, 5, &hostname)) {
        config.hostname = hostname;
    } else {
        print_help("Missing hostname");
        return false;
    }

    return true;
}

bool file_exists(const char* filename)
{
    return (access(filename, R_OK) == 0);
}

bool load_key_from_file(const char* filename)
{
    FILE* f;
    f = fopen(filename, "r");
    if (f == NULL) {
        return false;
    }

    // if the read failed the key is invalid and we will fail later.
    fread(config.keyPemBuffer, 1, MAX_KEY_PEM_SIZE, f);

    fclose(f);
    return true;
}

void handle_coap_get_request(NabtoDeviceCoapRequest* request, void* data)
{
    printf("Received CoAP GET request" NEWLINE);
    const char* responseData = "helloWorld";
    NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
    nabto_device_coap_response_set_code(response, 205);
    nabto_device_coap_response_set_content_format(response, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);
    nabto_device_coap_response_set_payload(response, responseData, strlen(responseData));
    nabto_device_coap_response_ready(response);
}

void handle_coap_post_request(NabtoDeviceCoapRequest* request, void* data)
{
    const char* responseData = "helloWorld";
    uint16_t contentFormat;
    NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
    nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8) {
        const char* responseData = "Invalid content format";
        printf("Received CoAP POST request with invalid content format" NEWLINE);
        nabto_device_coap_response_set_code(response, 400);
        nabto_device_coap_response_set_payload(response, responseData, strlen(responseData));
        nabto_device_coap_response_ready(response);
    } else {
        char* payload = (char*)malloc(1500);
        size_t payloadLength;
        nabto_device_coap_request_get_payload(request, (void**)&payload, &payloadLength);
        printf("Received CoAP POST request with a %li byte payload: " NEWLINE "%s", payloadLength, payload);
        nabto_device_coap_response_set_code(response, 205);
        nabto_device_coap_response_set_payload(response, responseData, strlen(responseData));
        nabto_device_coap_response_set_content_format(response, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);
        nabto_device_coap_response_ready(response);
    }
}

void stream_closed_callback(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data)
{
    struct streamContext* streamContext = (struct streamContext*)data;
    nabto_device_future_free(fut);
    nabto_device_stream_free(streamContext->stream);
    free(streamContext);
}

void close_stream(struct streamContext* streamContext)
{
    NabtoDeviceFuture* fut = nabto_device_stream_close(streamContext->stream);
    nabto_device_future_set_callback(fut, &stream_closed_callback, streamContext);
}

void stream_write_callback(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data)
{
    struct streamContext* streamContext = (struct streamContext*)data;
    nabto_device_future_free(fut);
    if (err == NABTO_DEVICE_EC_FAILED) {
        printf("stream closed or aborted");
        close_stream(streamContext);
        return;
    }
    memset(streamContext->buffer, 0, 1500);
    fut = nabto_device_stream_read_some(streamContext->stream, streamContext->buffer, 1500, &streamContext->read);
    nabto_device_future_set_callback(fut, &stream_read_callback, streamContext);
}

void stream_read_callback(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data)
{
    struct streamContext* streamContext = (struct streamContext*)data;
    nabto_device_future_free(fut);
    if (err == NABTO_DEVICE_EC_FAILED) {
        printf("stream closed or aborted" NEWLINE);
        close_stream(streamContext);
        return;
    }
    printf("read %lu bytes into buf: ", streamContext->read);
    printf("%s" NEWLINE, streamContext->buffer);

    fut = nabto_device_stream_write(streamContext->stream, streamContext->buffer, streamContext->read);
    nabto_device_future_set_callback(fut, &stream_write_callback, streamContext);
    return;
}

void handle_new_stream(struct streamContext* streamContext)
{
    NabtoDeviceFuture* fut = nabto_device_stream_accept(streamContext->stream);
    nabto_device_future_wait(fut);
    if (nabto_device_future_error_code(fut) != NABTO_DEVICE_EC_OK) {
        printf("stream accept failed, dropping stream");
        nabto_device_stream_free(streamContext->stream);
        free(streamContext);
        return;
    }
    fut = nabto_device_stream_read_some(streamContext->stream, streamContext->buffer, 1500, &streamContext->read);
    nabto_device_future_set_callback(fut, &stream_read_callback, streamContext);
}

void run_device()
{
    NabtoDeviceError ec;
    NabtoDeviceStream* stream;
    NabtoDevice* dev = nabto_device_new();
    nabto_device_set_std_out_log_callback();

    ec = nabto_device_set_private_key(dev, config.keyPemBuffer);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }
    ec = nabto_device_set_server_url(dev, config.hostname);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }

    char fingerprint[33];
    memset(fingerprint, 0, 33);
    ec = nabto_device_get_device_fingerprint_hex(dev, fingerprint);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }

    printf("Starting device productid: %s, deviceid: %s, fingerprint: %s" NEWLINE, config.productId, config.deviceId, fingerprint);

    ec = nabto_device_start(dev);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }

    nabto_device_coap_add_resource(dev, NABTO_DEVICE_COAP_GET, "/test/get", &handle_coap_get_request, dev);
    nabto_device_coap_add_resource(dev, NABTO_DEVICE_COAP_POST, "/test/post", &handle_coap_post_request, dev);

    // wait for ctrl-c
    while (true) {
        NabtoDeviceFuture* fut = nabto_device_stream_listen(dev, &stream);
        nabto_device_future_wait(fut);
        if (nabto_device_future_error_code(fut) != NABTO_DEVICE_EC_OK) {
            printf("Stream listen returned with an error");
            return;
        }
        nabto_device_future_free(fut);
        struct streamContext* strCtx = malloc(sizeof(struct streamContext));
        strCtx->stream = stream;
        handle_new_stream(strCtx);
    }
}

int main(int argc, const char** argv)
{
    memset(&config, 0, sizeof(struct config));
    if (!parse_args(argc, argv)) {
        exit(1);
    }

    if (!load_key_from_file(config.keyFile)) {
        print_help("keyfile could not be read");
        exit(1);
    }

    run_device();

    // TODO start a device
    // TODO add streaming and coap handlers

}
