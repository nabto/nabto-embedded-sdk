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
#include <stdlib.h>

/**
 * Simple service invocation device.
 *
 * Once the device is attached it makes a request to the service id with the given message.
 */

const char* keyFile = "device.key";

static bool start_device(NabtoDevice* device, const char* productId, const char* deviceId);
static void handle_device_error(NabtoDevice* d, NabtoDeviceListener* l, char* msg);
static void wait_for_device_events(NabtoDevice* device);
static void signal_handler(int s);
static void service_invocation(NabtoDevice* device);

NabtoDevice* device_;
const char* message_;
const char* serviceId_;

int main(int argc, char* argv[]) {

    if (argc != 5) {
        printf("The example takes exactly four arguments. %s <product-id> <device-id> <service-id> <message>" NEWLINE, argv[0]);
        return -1;
    }

    char* productId = argv[1];
    char* deviceId = argv[2];
    serviceId_ = argv[3];
    message_ = argv[4];

    printf("Nabto Embedded SDK Version %s\n", nabto_device_version());

    if ((device_ = nabto_device_new()) == NULL) {
        handle_device_error(NULL, NULL, "Failed to allocate device");
        return -1;
    }

    if (!start_device(device_, productId, deviceId)) {
        handle_device_error(device_, NULL, "Failed to start device");
        return -1;
    }

    signal(SIGINT, &signal_handler);

    wait_for_device_events(device_);

    nabto_device_stop(device_);
    nabto_device_free(device_);

    printf("Device cleaned up and closing\n");
}

void signal_handler(int s)
{
    NabtoDeviceFuture* fut = nabto_device_future_new(device_);
    nabto_device_close(device_, fut); // triggers NABTO_DEVICE_EVENT_CLOSED in event listener
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
}

void service_invocation(NabtoDevice* device)
{
    NabtoDeviceServiceInvoke* invocation = nabto_device_service_invoke_new(device);
    nabto_device_service_invoke_set_service_id(invocation, serviceId_);
    nabto_device_service_invoke_set_message(invocation, (const uint8_t*)message_, sizeof(message_));
    NabtoDeviceFuture* future = nabto_device_future_new(device);
    nabto_device_service_invoke_execute(invocation, future);
    NabtoDeviceError ec = nabto_device_future_wait(future);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Service invocation failed %s\n", nabto_device_error_get_message(ec));
    } else {
        uint16_t statusCode = nabto_device_service_invoke_get_response_status_code(invocation);
        const uint8_t* message = nabto_device_service_invoke_get_response_message_data(invocation);
        size_t messageLength = nabto_device_service_invoke_get_response_message_size(invocation);
        printf("Service invocation ok. StatusCode: %d, MessageLength: %d\n", statusCode, (int)messageLength);
    }
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
            service_invocation(device_);
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

    const char* server = getenv("NABTO_SERVER");
    if (server) {
        nabto_device_set_server_url(device, server);
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
