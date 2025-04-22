#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <apps/common/string_file.h>

#include <modules/fs/posix/nm_fs_posix.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

const char* appName = "simple_tunnel";
const char* sct = "demosct";

typedef struct {
    const char* host;
    const char* id;
    const char* type;
    uint16_t port;
} service_t;

// TCP tunnel configuration.
const service_t ssh = {
    .host = "127.0.0.1",
    .id   = "ssh",
    .type = "ssh",
    .port = 22
};

const service_t rtsp = {
    .host = "127.0.0.1",
    .id   = "rtsp",
    .type = "rtsp",
    .port = 554
};


int serviceConcurrentConnectionsLimit = -1;

#define NEWLINE "\n"

void signal_handler(int s);
NabtoDeviceError load_or_create_private_key();

NabtoDevice* device = NULL;

int main(int argc, char** argv) {
    NabtoDeviceError ec = 0;
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

    ec = nabto_device_add_server_connect_token(device, sct);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Failed to add server connect token: %s" NEWLINE,
               nabto_device_error_get_message(ec));
        goto cleanup;
    }

    nabto_device_enable_mdns(device);

    nabto_device_set_log_std_out_callback(device);

    /**
     * This is the tunnel specific function all the other code is boiler plate code.
     */
    service_t services[] = {
        ssh,
        rtsp
    };
    int serviceCount = sizeof(services)/sizeof(services[0]);
    for (int i = 0; i < serviceCount; i++) {
        service_t* service = &services[i];
        ec = nabto_device_add_tcp_tunnel_service(device, service->id, service->type, service->host, service->port);
        if (ec != NABTO_DEVICE_EC_OK) {
            printf("Failed to add the tunnel service. %s" NEWLINE, nabto_device_error_get_message(ec));
            goto cleanup;
        } else {
            printf("Added a TCP Tunnel service. Id: %s, type: %s, host: %s, port: %d" NEWLINE,
                   service->id, service->type, service->host, service->port);
        }

        ec = nabto_device_limit_tcp_tunnel_connections(device, service->type, serviceConcurrentConnectionsLimit);
        if (ec != NABTO_DEVICE_EC_OK) {
            printf("Failed to limit the tunnel service. %s" NEWLINE, nabto_device_error_get_message(ec));
            goto cleanup;
        }
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
        }
        nabto_device_authorization_request_verdict(authorizationRequest, true);
        nabto_device_authorization_request_free(authorizationRequest);
        authorizationRequest = NULL;
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
    NabtoDeviceError ec = 0;
    const char* privateKeyFileName = "device.key";
    struct nm_fs fsImpl = nm_fs_posix_get_impl();
    if (!string_file_exists(&fsImpl, privateKeyFileName)) {
        char* privateKey = NULL;
        ec = nabto_device_create_private_key(device, &privateKey);
        if (ec != NABTO_DEVICE_EC_OK) {
            return ec;
        }
        string_file_save(&fsImpl, privateKeyFileName, privateKey);
        nabto_device_string_free(privateKey);
    }

    char* privateKey = NULL;
    if (!string_file_load(&fsImpl, privateKeyFileName, &privateKey)) {
        return NABTO_DEVICE_EC_INVALID_STATE;
    }
    ec = nabto_device_set_private_key(device, privateKey);
    free(privateKey);
    return ec;
}
