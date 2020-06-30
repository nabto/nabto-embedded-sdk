#include <stdio.h>
#include <nabto/nabto_device.h>
#include "device_event_handler.h"

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <stdbool.h>
#include <stdio.h>
#include <signal.h>

char* productId = "pr-ndkobnzf";
const char* deviceId = "de-74kprodc";
const char* serverUrl = "a.devices.dev.nabto.net";

char* privateKey =
    "-----BEGIN EC PARAMETERS-----\n"
    "BggqhkjOPQMBBw==\n"
    "-----END EC PARAMETERS-----\n"
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEINc9q3Ku6iIHUh44y1/8zUAOYL2+f1JEd96so+D336KQoAoGCCqGSM49\n"
    "AwEHoUQDQgAEx847zIaCSk8zvZ6XsQzBKyDiv5RrqtxLGQWvGl85lZjn6Y3gdU1a\n"
    "YcJ7P/1GQlbCuorDFqtiWGEPpGoIju07mg==\n"
    "-----END EC PRIVATE KEY-----\n";

const char* coapPath[] = { "hello-world", NULL };
const char* helloWorld = "Hello world";

struct context {
    NabtoDeviceCoapRequest* request;
    NabtoDeviceListener* listener;
};

void request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data);
bool start_device(NabtoDevice* device);
void handle_coap_request(NabtoDeviceCoapRequest* request);
void handle_device_error(NabtoDevice* d, NabtoDeviceListener* l, char* msg);
void wait_for_device_events(NabtoDevice* device);
void signal_handler(int s);

NabtoDevice* device_;

int main(void) {
    NabtoDeviceError ec;
    struct context ctx;

    printf("Nabto Embedded SDK Version %s\n", nabto_device_version());

    device_ = nabto_device_new();
    if (device_ == NULL) {
        handle_device_error(NULL, NULL, "Failed to allocate device");
        return -1;
    }

    if (!start_device(device_)) {
        handle_device_error(device_, NULL, "Failed to start device");
        return -1;
    }

    ctx.listener = nabto_device_listener_new(device_);
    if (ctx.listener == NULL) {
        handle_device_error(device_, NULL, "Failed to allocate listener");
        return -1;
    }

    ec = nabto_device_coap_init_listener(device_, ctx.listener, NABTO_DEVICE_COAP_GET, coapPath);
    if (ec != NABTO_DEVICE_EC_OK) {
        handle_device_error(device_, ctx.listener, "CoAP listener initialization failed");
        return -1;
    }

    NabtoDeviceFuture* future = nabto_device_future_new(device_);
    if (future == NULL) {
        handle_device_error(device_, ctx.listener, "Failed to allocate future");
        return -1;
    }

    nabto_device_listener_new_coap_request(ctx.listener, future, &ctx.request);
    nabto_device_future_set_callback(future, &request_callback, &ctx);

    signal(SIGINT, &signal_handler);

    wait_for_device_events(device_);

    nabto_device_listener_free(ctx.listener);
    nabto_device_stop(device_);
    nabto_device_free(device_);
    nabto_device_future_free(future);

    printf("Device cleaned up and closing\n");
}

void signal_handler(int s)
{
    NabtoDeviceFuture* fut = nabto_device_future_new(device_);
    nabto_device_close(device_, fut); // triggers NABTO_DEVICE_EVENT_CLOSED in event listener
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
}

void wait_for_device_events(NabtoDevice* device) {
    struct device_event_handler eventHandler;
    device_event_handler_init(&eventHandler, device);
    device_event_handler_blocking_listener(&eventHandler);
    nabto_device_stop(device);
    device_event_handler_deinit(&eventHandler);
}

bool start_device(NabtoDevice* device)
{
    NabtoDeviceError ec;
    char* fp;
    ec = nabto_device_set_private_key(device, privateKey);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Failed to set private key, ec=%d\n", ec);
        return false;
    }

    ec = nabto_device_get_device_fingerprint_hex(device, &fp);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }

    printf("Device: %s.%s with fingerprint: [%s]\n", productId, deviceId, fp);
    nabto_device_string_free(fp);

    ec = nabto_device_set_product_id(device, productId);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    ec = nabto_device_set_device_id(device, deviceId);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    ec = nabto_device_set_server_url(device, serverUrl);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    ec = nabto_device_enable_mdns(device);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    ec = nabto_device_set_log_std_out_callback(device);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    ec = nabto_device_start(device);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }
    return true;
}


void request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
{
    struct context* ctx = (struct context*)data;
    if (ec == NABTO_DEVICE_EC_OK) {
        handle_coap_request(ctx->request);
        nabto_device_listener_new_coap_request(ctx->listener, fut, &(ctx->request));
        nabto_device_future_set_callback(fut, &request_callback, ctx);
    } else if (ec == NABTO_DEVICE_EC_STOPPED) {
        // stop invoked - cleanup triggered from main
    } else {
        printf("An error occurred when handling CoAP request, ec=%d\n", ec);
    }
}

void handle_coap_request(NabtoDeviceCoapRequest* request)
{
    nabto_device_coap_response_set_code(request, 205);
    nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);

    NabtoDeviceError ec = nabto_device_coap_response_set_payload(request, helloWorld, strlen(helloWorld));
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 500, NULL);
    } else {
        nabto_device_coap_response_ready(request);
    }
    printf("Responded to CoAP request\n");
    nabto_device_coap_request_free(request);
}

void handle_device_error(NabtoDevice* d, NabtoDeviceListener* l, char* msg)
{
    NabtoDeviceFuture* f = nabto_device_future_new(d);
    if (d) {
        nabto_device_close(d, f);
        nabto_device_future_wait(f);
        nabto_device_stop(d);
        nabto_device_free(d);
    }
    if (f) {
        nabto_device_future_free(f);
    }
    if (l) {
        nabto_device_listener_free(l);
    }
    printf("%s", msg);
}
