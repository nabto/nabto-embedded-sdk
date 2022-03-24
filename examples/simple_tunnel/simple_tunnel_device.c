#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <apps/common/string_file.h>

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

const char* appName = "simple_tunnel";

// TCP tunnel configuration.
const char* serviceHost = "127.0.0.1";
uint16_t    servicePort = 22;
const char* serviceId   = "ssh";
const char* serviceType = "ssh";
int         serviceConcurrentConnectionsLimit = -1;

#define NEWLINE "\n"

void signal_handler(int s);
NabtoDeviceError load_or_create_private_key();

NabtoDevice* device = NULL;

int main(int argc, char** argv) {
    NabtoDeviceError ec;
    NabtoDeviceFuture* future = NULL;
    NabtoDeviceListener* authorizationListener = NULL;
    NabtoDeviceAuthorizationRequest* authorizationRequest = NULL;
    char* deviceFingerprint = NULL;

    if (argc != 3) {
        printf("The example takes exactly two arguments. %s <product-id> <device-id>" NEWLINE, argv[0]);
        return -1;
    }

    char* productId = argv[1];
    char* deviceId = argv[2];

    printf("Nabto Embedded SDK Version %s\n", nabto_device_version());

    device = nabto_device_new();
    future = nabto_device_future_new(device);
    authorizationListener = nabto_device_listener_new(device);

    if (device == NULL || future == NULL || authorizationListener == NULL) {
        printf("Could not allocate resources" NEWLINE);
        goto cleanup;
    }

    ec = load_or_create_private_key();
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Could not load or create the private key. %s" NEWLINE, nabto_device_error_get_message(ec));
        goto cleanup;
    }

    ec = nabto_device_set_product_id(device, productId);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Failed to set product id. %s" NEWLINE, nabto_device_error_get_message(ec));
        goto cleanup;
    }

    ec = nabto_device_set_device_id(device, deviceId);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Failed to set device id. %s" NEWLINE, nabto_device_error_get_message(ec));
        goto cleanup;
    }

    const char* server = getenv("NABTO_SERVER");
    if (server) {
        if (nabto_device_set_server_url(device, server) != NABTO_DEVICE_EC_OK) {
            goto cleanup;
        }
    }

    ec = nabto_device_set_app_name(device, appName);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Failed to set app name. %s" NEWLINE, nabto_device_error_get_message(ec));
        goto cleanup;
    }

    ec = nabto_device_set_log_level(device, "info");
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Could not set log level. %s" NEWLINE, nabto_device_error_get_message(ec));
        goto cleanup;
    }

    nabto_device_enable_mdns(device);

    nabto_device_set_log_std_out_callback(device);

    /**
     * This is the tunnel specific function all the other code is boiler plate code.
     */
    ec = nabto_device_add_tcp_tunnel_service(device, serviceId, serviceType, serviceHost, servicePort);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Failed to add the tunnel service. %s" NEWLINE, nabto_device_error_get_message(ec));
        goto cleanup;
    } else {
        printf("Added a TCP Tunnel service. Id: %s, type: %s, host: %s, port: %d" NEWLINE, serviceId, serviceType, serviceHost, servicePort);
    }

    ec = nabto_device_limit_tcp_tunnel_connections(device, serviceType, serviceConcurrentConnectionsLimit);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Failed to limit the tunnel service. %s" NEWLINE, nabto_device_error_get_message(ec));
        goto cleanup;
    }

    ec = nabto_device_get_device_fingerprint(device, &deviceFingerprint);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Could not get the fingerprint. %s" NEWLINE, nabto_device_error_get_message(ec));
        goto cleanup;
    }

    printf("Configuration:" NEWLINE);
    printf("ProductId:   %s" NEWLINE, productId);
    printf("DeviceId:    %s" NEWLINE, deviceId);
    printf("Fingerprint: %s" NEWLINE, deviceFingerprint);

    nabto_device_start(device, future);
    ec = nabto_device_future_wait(future);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("could not start the device. %s" NEWLINE, nabto_device_error_get_message(ec));
        goto cleanup;
    }

    // wait for ctrl+c
    signal(SIGINT, &signal_handler);

    // When a tunnel is created an authorization request is made, allow all
    // these authorization requests.
    ec = nabto_device_authorization_request_init_listener(device, authorizationListener);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("could not init the authorization request listener. %s" NEWLINE, nabto_device_error_get_message(ec));
        goto cleanup;
    }


    while (true) {
        nabto_device_listener_new_authorization_request(authorizationListener, future, &authorizationRequest);
        ec = nabto_device_future_wait(future);
        if (ec != NABTO_DEVICE_EC_OK) {
            break;
        } else {
            nabto_device_authorization_request_verdict(authorizationRequest, true);
            nabto_device_authorization_request_free(authorizationRequest);
            authorizationRequest = NULL;
        }
    }

 cleanup:
    nabto_device_stop(device);

    nabto_device_string_free(deviceFingerprint);
    nabto_device_listener_free(authorizationListener);
    nabto_device_future_free(future);
    nabto_device_free(device);
}

void signal_handler(int s)
{
    printf("Got signal %d" NEWLINE, s);
    NabtoDeviceFuture* future = nabto_device_future_new(device);
    nabto_device_close(device, future);
    nabto_device_future_wait(future);
    nabto_device_future_free(future);
    // also stops the authorization listener.
    nabto_device_stop(device);
}

NabtoDeviceError load_or_create_private_key()
{
    NabtoDeviceError ec;
    const char* privateKeyFileName = "device.key";
    if (!string_file_exists(privateKeyFileName)) {
        char* privateKey;
        ec = nabto_device_create_private_key(device, &privateKey);
        if (ec != NABTO_DEVICE_EC_OK) {
            return ec;
        }
        string_file_save(privateKeyFileName, privateKey);
        nabto_device_string_free(privateKey);
    }

    char* privateKey;
    if (!string_file_load(privateKeyFileName, &privateKey)) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }
    ec = nabto_device_set_private_key(device, privateKey);
    free(privateKey);
    return ec;
}
