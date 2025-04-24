#include <apps/common/string_file.h>
#include <nabto/nabto_device.h>

#include <modules/fs/posix/nm_fs_posix.h>

#ifdef _WIN32
#include <Windows.h>
#define NEWLINE "\r\n"
#else
#include <unistd.h>
#define NEWLINE "\n"
#endif

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

const char* keyFile = "device.key";

static const char* coapPath[] = { "hello-world", NULL };
const char* defaultString = "Hello world";
const char* sct = "demosct";
char helloWorld[128];

struct context {
    NabtoDevice* device;
    NabtoDeviceFuture* startFuture;
    NabtoDeviceFuture* getFuture;
    NabtoDeviceFuture* postFuture;
    NabtoDeviceFuture* closeFuture;
    NabtoDeviceFuture* deviceEventFuture;

    NabtoDeviceListener* getListener;
    NabtoDeviceListener* postListener;
    NabtoDeviceListener* deviceEventListener;

    NabtoDeviceCoapRequest* getRequest;

    NabtoDeviceCoapRequest* postRequest;
};

void get_request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data);
void post_request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data);
bool start_device(struct context* ctxc, const char* productId, const char* deviceId);
void handle_coap_get_request(NabtoDeviceCoapRequest* request);
void handle_coap_post_request(NabtoDeviceCoapRequest* request);
void handle_device_error(struct context* ctx, char* msg);
void wait_for_device_events(struct context* ctx);
void signal_handler(int s);

static bool allocate_context(struct context* c);
static void free_context(struct context* c);
static int main_with_ctx(int argc, char* argv[], struct context* ctx);

NabtoDevice* device_;

static bool init_logging(void);

int main(int argc, char* argv[])
{
    if (argc != 3) {
        printf("The example takes exactly two arguments. %s <product-id> <device-id>" NEWLINE, argv[0]);
        return -1;
    }

    printf("Nabto Embedded SDK Version %s\n", nabto_device_version());

    struct context ctx;
    if (!allocate_context(&ctx)) {
        printf("Cannot allocate required objects\n");
        free_context(&ctx);
        return -1;
    }

    int status = main_with_ctx(argc, argv, &ctx);

    free_context(&ctx);
    return status;
}

int main_with_ctx(int argc, char* argv[], struct context* ctx)
{
    if (argc < 3) {
        return -1;
    }
    char* productId = argv[1];
    char* deviceId = argv[2];

    memcpy(helloWorld, defaultString, strlen(defaultString)+1);

    printf("Nabto Embedded SDK Version %s\n", nabto_device_version());

    if (!init_logging()) {
        handle_device_error(ctx, "Failed to initialize logging");
        return -1;
    }



    device_ = ctx->device;

    if (!start_device(ctx, productId, deviceId)) {
        handle_device_error(ctx, "Failed to start device");
        return -1;
    }

    if (nabto_device_coap_init_listener(ctx->device, ctx->getListener, NABTO_DEVICE_COAP_GET, coapPath) != NABTO_DEVICE_EC_OK) {
        handle_device_error(ctx, "CoAP listener initialization failed");
        return -1;
    }

    // both post and get handler can exist on the same path. Different paths are also ok
    if (nabto_device_coap_init_listener(ctx->device, ctx->postListener, NABTO_DEVICE_COAP_POST, coapPath) != NABTO_DEVICE_EC_OK) {
        handle_device_error(ctx, "CoAP listener initialization failed");
        return -1;
    }

    nabto_device_listener_new_coap_request(ctx->getListener, ctx->getFuture, &ctx->getRequest);
    nabto_device_future_set_callback(ctx->getFuture, &get_request_callback, ctx);

    nabto_device_listener_new_coap_request(ctx->postListener, ctx->postFuture, &ctx->postRequest);
    nabto_device_future_set_callback(ctx->postFuture, &post_request_callback, ctx);



    signal(SIGINT, &signal_handler);

    wait_for_device_events(ctx);

    nabto_device_stop(ctx->device);

    return 0;
}

bool init_logging(void) {
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
    if (fut == NULL) {
        printf("cannot allocate future for nice shutdown\n");
        exit(1);
    }
    nabto_device_close(device_, fut); // triggers NABTO_DEVICE_EVENT_CLOSED in event listener
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
}

void wait_for_device_events(struct context* ctx) {
    NabtoDeviceEvent event = 0;
    nabto_device_device_events_init_listener(ctx->device, ctx->deviceEventListener);
    while(true) {
        nabto_device_listener_device_event(ctx->deviceEventListener, ctx->deviceEventFuture, &event);
        NabtoDeviceError ec = nabto_device_future_wait(ctx->deviceEventFuture);
        if (ec != NABTO_DEVICE_EC_OK) {
            printf("Device event handler failed with %s\n", nabto_device_error_get_message(ec));
            break;
        }
        if (event == NABTO_DEVICE_EVENT_CLOSED) {
            printf("Device closed\n");
            break;
        }
        if (event == NABTO_DEVICE_EVENT_ATTACHED) {
            printf("Attached to the basestation\n");
        } else if (event == NABTO_DEVICE_EVENT_DETACHED) {
            printf("Detached from the basestation\n");
        } else if (event == NABTO_DEVICE_EVENT_UNKNOWN_FINGERPRINT) {
            printf("The device fingerprint is not known by the basestation\n");
        } else if (event == NABTO_DEVICE_EVENT_WRONG_PRODUCT_ID) {
            printf("The provided Product ID did not match the fingerprint\n");
        } else if (event == NABTO_DEVICE_EVENT_WRONG_DEVICE_ID) {
            printf("The provided Device ID did not match the fingerprint\n");
        } else if (event == NABTO_DEVICE_EVENT_WATCHDOG_FAILURE) {
            printf("Watchdog failure event!\n");
        }
    }
    nabto_device_stop(ctx->device);
}

bool start_device(struct context* ctx, const char* productId, const char* deviceId)
{
    NabtoDeviceError ec = 0;
    char* privateKey = NULL;
    char* fp = NULL;

    struct nm_fs fsImpl = nm_fs_posix_get_impl();



    if (!string_file_exists(&fsImpl, keyFile)) {
        ec = nabto_device_create_private_key(ctx->device, &privateKey);
        if (ec != NABTO_DEVICE_EC_OK) {
            printf("Failed to create private key, ec=%s\n", nabto_device_error_get_message(ec));
            return false;
        }
        if (!string_file_save(&fsImpl, keyFile, privateKey)) {
            printf("Failed to persist private key to file: %s\n", keyFile);
            nabto_device_string_free(privateKey);
            return false;
        }
        nabto_device_string_free(privateKey);
    }

    if (!string_file_load(&fsImpl, keyFile, &privateKey)) {
        printf("Failed to load private key from file: %s\n", keyFile);
        return false;
    }

    ec = nabto_device_set_private_key(ctx->device, privateKey);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Failed to set private key, ec=%s\n", nabto_device_error_get_message(ec));
        return false;
    }

    free(privateKey);

    if (nabto_device_get_device_fingerprint(ctx->device, &fp) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    printf("Device: %s.%s with fingerprint: [%s]\n", productId, deviceId, fp);
    nabto_device_string_free(fp);

    const char* disableMdns = getenv("NABTO_DISABLE_MDNS");
    if (disableMdns == NULL) {
        if (nabto_device_enable_mdns(ctx->device) != NABTO_DEVICE_EC_OK) {
            return false;
        }
    }

    if (nabto_device_set_product_id(ctx->device, productId) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_device_id(ctx->device, deviceId) != NABTO_DEVICE_EC_OK ||
        nabto_device_add_server_connect_token(ctx->device, sct) != NABTO_DEVICE_EC_OK)
    {
        return false;
    }

    const char* server = getenv("NABTO_SERVER");
    if (server) {
        if (nabto_device_set_server_url(ctx->device, server) != NABTO_DEVICE_EC_OK) {
            return false;
        }
    }

    nabto_device_start(ctx->device, ctx->startFuture);

    ec = nabto_device_future_wait(ctx->startFuture);
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
    char* payload = NULL;
    size_t len = 0;
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
    nabto_device_coap_response_set_code(request, 204);
    nabto_device_coap_response_ready(request);
    printf("CoAP response changed to %s by CoAP Post request\n", payload);
    nabto_device_coap_request_free(request);
}

void handle_device_error(struct context* ctx, char* msg)
{
    nabto_device_close(ctx->device, ctx->closeFuture);
    nabto_device_future_wait(ctx->closeFuture);
    nabto_device_stop(ctx->device);

    printf("%s\n", msg);
}

bool allocate_context(struct context* c)
{
    memset(c, 0, sizeof(struct context));
    c->device = nabto_device_new();
    if (c->device == NULL) {
        return false;
    }

    c->startFuture = nabto_device_future_new(c->device);
    c->getFuture = nabto_device_future_new(c->device);
    c->postFuture = nabto_device_future_new(c->device);
    c->closeFuture = nabto_device_future_new(c->device);
    c->deviceEventFuture = nabto_device_future_new(c->device);

    c->getListener = nabto_device_listener_new(c->device);
    c->postListener = nabto_device_listener_new(c->device);
    c->deviceEventListener = nabto_device_listener_new(c->device);

    if (c->startFuture == NULL ||
        c->getFuture == NULL ||
        c->postFuture == NULL ||
        c->closeFuture == NULL ||
        c->deviceEventFuture == NULL ||
        c->getListener == NULL ||
        c->postListener == NULL ||
        c->deviceEventListener == NULL)
    {
        return false;
    }
    return true;
}

void free_context(struct context* ctx)
{
    nabto_device_listener_free(ctx->deviceEventListener);
    nabto_device_listener_free(ctx->postListener);
    nabto_device_listener_free(ctx->getListener);
    nabto_device_future_free(ctx->deviceEventFuture);
    nabto_device_future_free(ctx->closeFuture);
    nabto_device_future_free(ctx->postFuture);
    nabto_device_future_free(ctx->getFuture);
    nabto_device_future_free(ctx->startFuture);
    nabto_device_free(ctx->device);
}
