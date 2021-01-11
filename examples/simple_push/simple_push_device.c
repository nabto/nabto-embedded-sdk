#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
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

const char* rootCert =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBpTCCAUqgAwIBAgIUev5miQGPmjlHmisQJ5iYiq+Lf0kwCgYIKoZIzj0EAwIw\n"
    "MDELMAkGA1UEBhMCREsxDTALBgNVBAoMBFRlc3QxEjAQBgNVBAMMCVRlc3QgUm9v\n"
    "dDAeFw0yMDA2MjAwMDAwMDBaFw00OTEyMzEyMzU5NTlaMDAxCzAJBgNVBAYTAkRL\n"
    "MQ0wCwYDVQQKDARUZXN0MRIwEAYDVQQDDAlUZXN0IFJvb3QwWTATBgcqhkjOPQIB\n"
    "BggqhkjOPQMBBwNCAATWs9bVLhO8o+42UrDFZocbMjvt20ODDwjxjC5/lSKo8KU6\n"
    "yPcBsI6IMg+CfMfQpza7V5m9c/mHXw1r8iiOrizio0IwQDAdBgNVHQ4EFgQUcqIP\n"
    "gyPbvPkv4JCNZ/Al3yXTvI4wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC\n"
    "AYYwCgYIKoZIzj0EAwIDSQAwRgIhAKjXktlBZjxURdyDvlvPUn73cNz8MOTs7wl3\n"
    "ogsvei0AAiEA4r6s8iI6b37agG6zXsPKXwjTw3jS4acs1feiZ4Vo1NE=\n"
    "-----END CERTIFICATE-----\n";

const char* projectId = "edge-push-guide-example";
// Working token for edge-push-guide-example
const char* notification = "{\"message\": { \"notification\": { \"title\": \"Hello\", \"body\": \"World\" }, \"token\": \"fDD8WUAQRn2PxfC1vxvHCt:APA91bGP0RIxSGGDQroOte6XsKAteuyDvw5CwZyyaK0JRdElvBivAFBqiVjyfjUzmSS_Ekq68sNNeK7swED9Wn8qn-1OYcKuc49Jq0y6AcJ1UVjjzR23EHqXt9RVcfOGszMlp2pqBZIa\" } }";

const char* keyFile = "device.key";

const char* coapPath[] = { "hello-world", NULL };
const char* helloWorld = "Hello world";

struct context {
    NabtoDeviceCoapRequest* request;
    NabtoDeviceListener* listener;
};

void request_callback(NabtoDeviceFuture* fut, NabtoDeviceError ec, void* data);
bool start_device(NabtoDevice* device, const char* productId, const char* deviceId);
void handle_coap_request(NabtoDeviceCoapRequest* request);
void handle_device_error(NabtoDevice* d, NabtoDeviceListener* l, char* msg);
void wait_for_device_events(NabtoDevice* device);
void signal_handler(int s);

NabtoDevice* device_;

int main(int argc, char* argv[]) {

    if (argc != 3) {
        printf("The example takes exactly two arguments. %s <product-id> <device-id>" NEWLINE, argv[0]);
        return -1;
    }

    char* productId = argv[1];
    char* deviceId = argv[2];

    struct context ctx;

    printf("Nabto Embedded SDK Version %s\n", nabto_device_version());

    if ((device_ = nabto_device_new()) == NULL) {
        handle_device_error(NULL, NULL, "Failed to allocate device");
        return -1;
    }

    if (!start_device(device_, productId, deviceId)) {
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
            NabtoDeviceFcmNotification* n = nabto_device_fcm_notification_new(device);
            nabto_device_fcm_notification_set_project_id(n, projectId);
            nabto_device_fcm_notification_set_payload(n, notification);
            NabtoDeviceFuture* f = nabto_device_future_new(device);
            nabto_device_fcm_send(n, f);
            nabto_device_future_wait(f);
            nabto_device_future_free(f);
            nabto_device_fcm_notification_free(n);
        } else if (event == NABTO_DEVICE_EVENT_DETACHED) {
            printf("Detached from the basestation\n");
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

    if (nabto_device_get_device_fingerprint(device, &fp) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    printf("Device: %s.%s with fingerprint: [%s]\n", productId, deviceId, fp);
    nabto_device_string_free(fp);

    if (nabto_device_set_product_id(device, productId) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_device_id(device, deviceId) != NABTO_DEVICE_EC_OK ||
        nabto_device_enable_mdns(device) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_log_std_out_callback(device) != NABTO_DEVICE_EC_OK)
    {
        return false;
    }

    nabto_device_set_server_url(device, "localhost.nabto.net");
    nabto_device_set_server_port(device, 4433);
    nabto_device_set_root_certs(device, rootCert);

    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    nabto_device_start(device, fut);

    ec = nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
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
