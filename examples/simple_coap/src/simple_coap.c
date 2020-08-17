#include <stdio.h>
#include <nabto/nabto_device.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <stdbool.h>
#include <stdio.h>
#include <signal.h>

const char* productId = "pr-fatqcwj9";
const char* deviceId = "de-avmqjaxe";

char* privateKey =
    "-----BEGIN EC PARAMETERS-----\n"
    "BggqhkjOPQMBBw==\n"
    "-----END EC PARAMETERS-----\n"
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIFQmyvnY2Z+aJ9ridYS8YNKkqu8N+sXmGkixc050nwuRoAoGCCqGSM49\n"
    "AwEHoUQDQgAEptWJGX2AxsGwR405tPw9ljxHgzHYQvHHGpMBqoK8HGt5XPZ5xhtw\n"
    "6vaMXlCRijop6BYK5gtrIQM7r8ys4JqKoQ==\n"
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
    struct context ctx;

    printf("Nabto Embedded SDK Version %s\n", nabto_device_version());

    if ((device_ = nabto_device_new()) == NULL) {
        handle_device_error(NULL, NULL, "Failed to allocate device");
        return -1;
    }

    if (!start_device(device_)) {
        handle_device_error(device_, NULL, "Failed to start device");
        return -1;
    }

    if ((ctx.listener = nabto_device_listener_new(device_)) == NULL) {
        handle_device_error(device_, NULL, "Failed to allocate listener");
        return -1;
    }

    if (nabto_device_coap_init_listener(device_, ctx.listener, NABTO_DEVICE_COAP_GET, coapPath) != NABTO_DEVICE_EC_OK) {
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
    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    NabtoDeviceListener* listener = nabto_device_listener_new(device);
    NabtoDeviceEvent event;
    nabto_device_device_events_init_listener(device, listener);
    while(true) {
        nabto_device_listener_device_event(listener, fut, &event);
        if (nabto_device_future_wait(fut) != NABTO_DEVICE_EC_OK ||
            event == NABTO_DEVICE_EVENT_CLOSED) {
            break;
        } else if (event == NABTO_DEVICE_EVENT_ATTACHED) {
            printf("Attached to the basestation\n");
        } else if (event == NABTO_DEVICE_EVENT_DETACHED) {
            printf("Detached from the basestation\n");
        }
    }
    nabto_device_stop(device);
    nabto_device_future_free(fut);
    nabto_device_listener_free(listener);
}

bool start_device(NabtoDevice* device)
{
    NabtoDeviceError ec;
    char* fp;
    if ((ec = nabto_device_set_private_key(device, privateKey)) != NABTO_DEVICE_EC_OK) {
        printf("Failed to set private key, ec=%d\n", ec);
        return false;
    }

    if (nabto_device_get_device_fingerprint_full_hex(device, &fp) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    printf("Device: %s.%s with fingerprint: [%s]\n", productId, deviceId, fp);
    nabto_device_string_free(fp);

    if (nabto_device_set_product_id(device, productId) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_device_id(device, deviceId) != NABTO_DEVICE_EC_OK ||
        nabto_device_enable_mdns(device) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_log_std_out_callback(device) != NABTO_DEVICE_EC_OK ||
        nabto_device_start(device) != NABTO_DEVICE_EC_OK) {
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

    if (nabto_device_coap_response_set_payload(request, helloWorld, strlen(helloWorld)) == NABTO_DEVICE_EC_OK) {
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
