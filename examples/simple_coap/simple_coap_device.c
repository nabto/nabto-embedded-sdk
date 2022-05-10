#include <nabto/nabto_device.h>
#include <apps/common/string_file.h>

#ifdef _WIN32
#include <Windows.h>
#define NEWLINE "\r\n"
#else
#include <unistd.h>
#define NEWLINE "\n"
#endif

#include <stdbool.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

const char* keyFile = "device.key";

const char* coapPath[] = { "hello-world", NULL };
const char* defaultString = "Hello world hiii";
char helloWorld[128];

struct context {
    NabtoDeviceCoapRequest* getRequest;
    NabtoDeviceListener* getListener;
    NabtoDeviceCoapRequest* postRequest;
    NabtoDeviceListener* postListener;
};

void get_request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data);
void post_request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data);
bool start_device(NabtoDevice* device, const char* productId, const char* deviceId);
void handle_coap_get_request(NabtoDeviceCoapRequest* request);
void handle_coap_post_request(NabtoDeviceCoapRequest* request);
void handle_device_error(NabtoDevice* d, NabtoDeviceListener* l1, NabtoDeviceListener* l2, char* msg);
void wait_for_device_events(NabtoDevice* device);
void signal_handler(int s);

NabtoDevice* device_;

static bool init_logging();

int main(int argc, char* argv[]) {

    if (argc != 3) {
        printf("The example takes exactly two arguments. %s <product-id> <device-id>" NEWLINE, argv[0]);
        return -1;
    }

    char* productId = argv[1];
    char* deviceId = argv[2];

    memcpy(helloWorld, defaultString, strlen(defaultString));

    struct context ctx;

    printf("Nabto Embedded SDK Version %s\n", nabto_device_version());

    if (!init_logging()) {
        handle_device_error(NULL, NULL, NULL, "Failed to initialize logging");
        return -1;
    }

    if ((device_ = nabto_device_new()) == NULL) {
        handle_device_error(NULL, NULL, NULL, "Failed to allocate device");
        return -1;
    }

    if (!start_device(device_, productId, deviceId)) {
        handle_device_error(device_, NULL, NULL, "Failed to start device");
        return -1;
    }

    // Get handler setup
    if ((ctx.getListener = nabto_device_listener_new(device_)) == NULL) {
        handle_device_error(device_, NULL, NULL, "Failed to allocate listener");
        return -1;
    }

    if (nabto_device_coap_init_listener(device_, ctx.getListener, NABTO_DEVICE_COAP_GET, coapPath) != NABTO_DEVICE_EC_OK) {
        handle_device_error(device_, ctx.getListener, NULL, "CoAP listener initialization failed");
        return -1;
    }

    NabtoDeviceFuture* getFuture = nabto_device_future_new(device_);
    if (getFuture == NULL) {
        handle_device_error(device_, ctx.getListener, NULL, "Failed to allocate future");
        return -1;
    }

    // Post handler setup
    if ((ctx.postListener = nabto_device_listener_new(device_)) == NULL) {
        nabto_device_future_free(getFuture);
        handle_device_error(device_, ctx.getListener, NULL,
                            "Failed to allocate post listener");
        return -1;
    }

    // both post and get handler can exist on the same path. Different paths are also ok
    if (nabto_device_coap_init_listener(device_, ctx.postListener, NABTO_DEVICE_COAP_POST, coapPath) != NABTO_DEVICE_EC_OK) {
        nabto_device_future_free(getFuture);
        handle_device_error(device_, ctx.getListener, ctx.postListener, "CoAP listener initialization failed");
        return -1;
    }

    NabtoDeviceFuture* postFuture = nabto_device_future_new(device_);
    if (getFuture == NULL) {
        nabto_device_future_free(getFuture);
        handle_device_error(device_, ctx.getListener, ctx.postListener, "Failed to allocate future");
        return -1;
    }

    nabto_device_listener_new_coap_request(ctx.getListener, getFuture, &ctx.getRequest);
    nabto_device_future_set_callback(getFuture, &get_request_callback, &ctx);

    nabto_device_listener_new_coap_request(ctx.postListener, postFuture, &ctx.postRequest);
    nabto_device_future_set_callback(postFuture, &post_request_callback, &ctx);



    signal(SIGINT, &signal_handler);

    wait_for_device_events(device_);

    nabto_device_listener_free(ctx.getListener);
    nabto_device_listener_free(ctx.postListener);
    nabto_device_stop(device_);
    nabto_device_free(device_);
    nabto_device_future_free(getFuture);
    nabto_device_future_free(postFuture);

    printf("Device cleaned up and closing\n");
}

bool init_logging() {
    if (nabto_device_set_log_std_out_callback(NULL) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    const char* logLevel = getenv("NABTO_LOG_LEVEL");
    if (logLevel != NULL) {
        if (nabto_device_set_log_level(NULL, logLevel) != NABTO_DEVICE_EC_OK) {
            printf("Could not set loglevel to %s\n", logLevel);
            return false;
        }
    }
    return true;
}

void signal_handler(int s)
{
    (void)s;
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
        } else if (event == NABTO_DEVICE_EVENT_UNKNOWN_FINGERPRINT) {
            printf("The device fingerprint is not known by the basestation\n");
        } else if (event == NABTO_DEVICE_EVENT_WRONG_PRODUCT_ID) {
            printf("The provided Product ID did not match the fingerprint\n");
        } else if (event == NABTO_DEVICE_EVENT_WRONG_DEVICE_ID) {
            printf("The provided Device ID did not match the fingerprint\n");
        }
    }
    nabto_device_stop(device);
    nabto_device_future_free(fut);
    nabto_device_listener_free(listener);
}

bool start_device(NabtoDevice* device, const char* productId, const char* deviceId)
{
    NabtoDeviceError ec;
    char* privateKey;
    char* fp;

    if (!string_file_exists(keyFile)) {
        if ((ec = nabto_device_create_private_key(device, &privateKey)) != NABTO_DEVICE_EC_OK) {
            printf("Failed to create private key, ec=%s\n", nabto_device_error_get_message(ec));
            return false;
        }
        if (!string_file_save(keyFile, privateKey)) {
            printf("Failed to persist private key to file: %s\n", keyFile);
            nabto_device_string_free(privateKey);
            return false;
        }
        nabto_device_string_free(privateKey);
    }

    if (!string_file_load(keyFile, &privateKey)) {
        printf("Failed to load private key from file: %s\n", keyFile);
        return false;
    }

    if ((ec = nabto_device_set_private_key(device, privateKey)) != NABTO_DEVICE_EC_OK) {
        printf("Failed to set private key, ec=%s\n", nabto_device_error_get_message(ec));
        return false;
    }

    free(privateKey);

    if (nabto_device_get_device_fingerprint(device, &fp) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    printf("Device: %s.%s with fingerprint: [%s]\n", productId, deviceId, fp);
    nabto_device_string_free(fp);

    if (nabto_device_set_product_id(device, productId) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_device_id(device, deviceId) != NABTO_DEVICE_EC_OK ||
        nabto_device_enable_mdns(device) != NABTO_DEVICE_EC_OK)
    {
        return false;
    }

    const char* server = getenv("NABTO_SERVER");
    if (server) {
        if (nabto_device_set_server_url(device, server) != NABTO_DEVICE_EC_OK) {
            return false;
        }
    }

    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    nabto_device_start(device, fut);

    ec = nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
    if (ec != NABTO_DEVICE_EC_OK) {
        return false;
    }

    return true;
}


void get_request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
{
    struct context* ctx = (struct context*)data;
    if (ec == NABTO_DEVICE_EC_OK) {
        handle_coap_get_request(ctx->getRequest);
        nabto_device_listener_new_coap_request(ctx->getListener, fut, &(ctx->getRequest));
        nabto_device_future_set_callback(fut, &get_request_callback, ctx);
    } else if (ec == NABTO_DEVICE_EC_STOPPED) {
        // stop invoked - cleanup triggered from main
    } else {
        printf("An error occurred when handling CoAP request, ec=%d\n", ec);
    }
}

void handle_coap_get_request(NabtoDeviceCoapRequest* request)
{
    nabto_device_coap_response_set_code(request, 205);
    nabto_device_coap_response_set_content_format(request, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);

    if (nabto_device_coap_response_set_payload(request, helloWorld, strlen(helloWorld)) == NABTO_DEVICE_EC_OK) {
        nabto_device_coap_response_ready(request);
    }
    printf("Responded to CoAP request\n");
    nabto_device_coap_request_free(request);
}

void post_request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data)
{
    struct context* ctx = (struct context*)data;
    if (ec == NABTO_DEVICE_EC_OK) {
        handle_coap_post_request(ctx->postRequest);
        nabto_device_listener_new_coap_request(ctx->postListener, fut, &(ctx->postRequest));
        nabto_device_future_set_callback(fut, &post_request_callback, ctx);
    } else if (ec == NABTO_DEVICE_EC_STOPPED) {
        // stop invoked - cleanup triggered from main
    } else {
        printf("An error occurred when handling CoAP POST request, ec=%d\n", ec);
    }
}

void handle_coap_post_request(NabtoDeviceCoapRequest* request)
{
    char* payload;
    size_t len;
    if (nabto_device_coap_request_get_payload(request, (void**)&payload, &len) != NABTO_DEVICE_EC_OK) {
        nabto_device_coap_error_response(request, 400, "Missing payload");
        return;
    }
    if (len > 128) {
        nabto_device_coap_error_response(request, 400, "Payload size limit exceeded");
        return;
    }
    memcpy(helloWorld, payload, len);
    helloWorld[len] = '\0';
    if(helloWorld[ ] == '1')
    {
        printf("flip_mirror");
    }
    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
    printf("CoAP response changed to %s by CoAP Post request\n", payload);
    nabto_device_coap_request_free(request);
}

void handle_device_error(NabtoDevice* d, NabtoDeviceListener* l1, NabtoDeviceListener* l2, char* msg)
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
    if (l1) {
        nabto_device_listener_free(l1);
    }
    if (l2) {
        nabto_device_listener_free(l2);
    }
    printf("%s\n", msg);
}
