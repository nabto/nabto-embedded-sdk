#include "tcp_tunnel.h"
#include "iam_config.h"
#include "tcp_tunnel_state.h"
#include "tcp_tunnel_services.h"
#include <apps/common/string_file.h>
#include <apps/common/device_config.h>
#include <apps/common/json_config.h>
#include <modules/iam/nm_iam_state.h>
#include <apps/common/random_string.h>
#include <modules/iam/nm_iam_serializer.h>

#include <cjson/cJSON.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#define NEWLINE "\r\n"
#else
#define NEWLINE "\n"
#endif

#define ARRAY_SIZE(array) (sizeof(array)/sizeof((array)[0]))

bool create_device_config_interactive(const char* file);
bool create_state_interactive(const char* file);
bool create_state_interactive_custom(const char* file);
bool create_state_default(const char* file);
bool create_services_interactive(const char* file);

bool yes_no();

int is_printable(char c) {
    return c >= 0x20 && c <= 0x7e;
}

bool tcp_tunnel_config_interactive(struct tcp_tunnel* tcpTunnel) {
    bool createDeviceConfig = false;
    if (string_file_exists(tcpTunnel->deviceConfigFile)) {
        printf("A device configuration already exists (%s)" NEWLINE "Do you want to recreate it? ", tcpTunnel->deviceConfigFile);
        createDeviceConfig = yes_no();
    } else {
        printf("No device configuration found. Creating configuration: %s." NEWLINE, tcpTunnel->deviceConfigFile);
        createDeviceConfig = true;
    }
    if (createDeviceConfig) {
        if (!create_device_config_interactive(tcpTunnel->deviceConfigFile)) {
            return false;
        }
    }
    printf(NEWLINE);

    bool createIamConfig = false;
    if (string_file_exists(tcpTunnel->iamConfigFile)) {
        printf("The IAM configuration already exists (%s)" NEWLINE "Do you want to recreate it? ", tcpTunnel->iamConfigFile);
        createIamConfig = yes_no();
    } else {
        printf("No IAM configuration found. Creating configuration: %s" NEWLINE, tcpTunnel->iamConfigFile);
        createIamConfig = true;
    }

    if (createIamConfig) {
        if (!iam_config_create_default(tcpTunnel->iamConfigFile)) {
            printf("The IAM configuration file %s could not be created." NEWLINE, tcpTunnel->iamConfigFile);
            return false;
        }
    }
    printf(NEWLINE);

    bool createIamState = false;

    if (string_file_exists(tcpTunnel->stateFile)) {
        printf("The IAM State already exists (%s)" NEWLINE "Do you want to recreate it? ", tcpTunnel->stateFile);
        createIamState = yes_no();
    } else {
        printf("No IAM state file found. Creating IAM state file: %s" NEWLINE, tcpTunnel->stateFile);
        createIamState = true;
    }
    if (createIamState) {
        if (!create_state_interactive(tcpTunnel->stateFile)) {
            printf("Could not create the IAM state %s" NEWLINE, tcpTunnel->stateFile);
            return false;
        }
    }
    printf(NEWLINE);

    bool createServices = false;

    if (string_file_exists(tcpTunnel->servicesFile)) {
        printf("The Tunnel Services configuration already exists (%s)" NEWLINE "Do you want to recreate it? ", tcpTunnel->servicesFile);
        createServices = yes_no();
    } else {
        printf("No Tunnel Services configuration found. Creating configuration file: %s" NEWLINE, tcpTunnel->stateFile);
        createServices = true;
    }
    if (createServices) {
        if (!create_services_interactive(tcpTunnel->servicesFile)) {
            printf("Could not create the service configuration %s" NEWLINE, tcpTunnel->servicesFile);
            return false;
        }
    }
    printf(NEWLINE);

    return true;
}

bool create_device_config_interactive(const char* file) {
    char productId[20];
    char deviceId[20];
    printf("The device configuration requires a Product ID and a Device ID, created in the Nabto Cloud Console." NEWLINE);
    printf("Product Id: ");
    if (scanf("%20s", productId) != 1) {
        return false;
    }
    printf("Device Id: ");
    if (scanf("%20s", deviceId) != 1) {
        return false;
    }

    struct device_config dc;
    memset(&dc, 0, sizeof(struct device_config));
    dc.productId = productId;
    dc.deviceId = deviceId;
    return save_device_config(file, &dc);
}

bool yes_no() {
    char yn = 0;
    do {
        if (yn == '\n') {

        } else {
            printf("[y/n]: ");
        }

        (void)scanf("%c", &yn);
        if (yn == 'y' || yn == 'Y') {
            return true;
        }
        if (yn == 'n' || yn == 'N') {
            return false;
        }
    } while( true );
}

bool create_state_interactive(const char* file)
{
    printf("The IAM State enables pairing modes, and determines what role to assign new users." NEWLINE);
    printf("Do you want to create a custom IAM State? ");
    bool createCustomIam = yes_no();
    if (createCustomIam) {
        printf("Creating custom iam configuration" NEWLINE);
        return create_state_interactive_custom(file);
    } else {
        printf("Use default iam" NEWLINE);
        return create_state_default(file);
    }
}

uint8_t get_int(uint8_t max ) {
    char in = 0;
    do {
        if (in == '\n') {
        } else {
            printf("[0-%d]: ", max);
        }

        (void)scanf("%c", &in);
        if (in >= '0' && in <= '0'+max) {
            return (uint8_t)(in - '0');
        }
    } while (true);
}

bool create_state_interactive_custom(const char* file) {
    const char* roles[] = {"Unpaired", "Guest", "Standard", "Administrator"};
    bool enableLocalInitialPairing;
    bool enableLocalOpenPairing;
    bool enablePasswordInvitePairing;
    bool enablePasswordOpenPairing;
    uint8_t pickedRole = 1; // Default = Guest

    printf("Enable Local Initial Pairing: ");
    enableLocalInitialPairing = yes_no();
    printf("Enable Local Open Pairing: ");
    enableLocalOpenPairing = yes_no();
    printf("Enable Password Invite Pairing: ");
    enablePasswordInvitePairing = yes_no();
    printf("Enable Password Open Pairing: ");
    enablePasswordOpenPairing = yes_no();

    printf(NEWLINE);
    if (!enableLocalInitialPairing && !enablePasswordInvitePairing) {
        printf("Both Local Initial Pairing and Password Invite Pairing modes are disabled. This means it will not be possible to create an Administrator of this device." NEWLINE);
        printf("If IAM management is not needed, this is perfectly fine." NEWLINE);
        printf("Continue with choices?: ");
        if (!yes_no()) {
            return create_state_interactive_custom(file);
        }
        printf(NEWLINE);
    }

    if (!enableLocalOpenPairing && !enablePasswordOpenPairing) {
        printf("You have not enabled any open pairing modes, however, administrators can still enable these at runtime. If so, new users must be assigned a role." NEWLINE);
    }
    printf("Which role should new users be assigned?" NEWLINE);
    printf("[0]: Unpaired      - only allowed pairing actions" NEWLINE);
    printf("[1]: Guest         - allowed pairing and manage own user actions [Default]" NEWLINE);
    printf("[2]: Standard      - Guest actions and Tunnelling" NEWLINE);
    printf("[3]: Administrator - Standard actions and management of users and pairing modes" NEWLINE);
    pickedRole = get_int(3);

    struct nm_iam_state* state = nm_iam_state_new();

    // scanf cannot recognize empty string on its own, so we use getchar in a more manual fashion here.
    // It's probably in our best interest to replace all usages of scanf eventually as it is not very robust.
    {
        // scanf will leave newline in the stdin stream, so we have to clear it first.
        char c;
        while ((c = getchar()) != '\n' && c != EOF);

        char friendlyName[16] = {0};
        int friendlyNameMax = sizeof(friendlyName);
        const char* defaultFriendlyName = "Tcp Tunnel";
        printf("Enter a friendly name for your device (max %i characters, empty string will default to \"%s\"): ", friendlyNameMax, defaultFriendlyName);

        int i = 0;
        while (c = getchar()) {
            // checking for is_printable handles the case on windows where newlines are \r\n
            if (c == '\n' || c == EOF) {
                break;
            }

            if (i < (friendlyNameMax-1) && is_printable(c)) {
                friendlyName[i++] = c;
            }
        }

        if (friendlyName[0] == 0) {
            nm_iam_state_set_friendly_name(state, defaultFriendlyName);
        } else {
            nm_iam_state_set_friendly_name(state, friendlyName);
        }
    }

    if (enableLocalInitialPairing ||
        enablePasswordInvitePairing) {  // admin user must be precreated
        const char* initialUsername = "admin";

        struct nm_iam_user* admin = nm_iam_state_user_new(initialUsername);

        nm_iam_state_user_set_role(admin, "Administrator");
        nm_iam_state_user_set_password(admin, random_password(12));
        nm_iam_state_user_set_sct(admin, random_password(12));

        nm_iam_state_add_user(state, admin);
        nm_iam_state_set_initial_pairing_username(state, initialUsername);
    }

    // Open pairing settings are still set if disabled in case admin enables at runtime
    nm_iam_state_set_password_open_password(state, random_password(12));
    nm_iam_state_set_password_open_sct(state, random_password(12));
    nm_iam_state_set_open_pairing_role(state, roles[pickedRole]);

    nm_iam_state_set_password_invite_pairing(state, enablePasswordInvitePairing);
    nm_iam_state_set_password_open_pairing(state, enablePasswordOpenPairing);
    nm_iam_state_set_local_initial_pairing(state, enableLocalInitialPairing);
    nm_iam_state_set_local_open_pairing(state, enableLocalOpenPairing);

    return save_tcp_tunnel_state(file, state);

}

bool create_state_default(const char* file)
{
    struct nm_iam_state* state = nm_iam_state_new();

    const char* initialUsername = "admin";

    struct nm_iam_user* admin = nm_iam_state_user_new(initialUsername);

    nm_iam_state_user_set_role(admin, "Administrator");
    nm_iam_state_user_set_password(admin, random_password(12));
    nm_iam_state_user_set_sct(admin, random_password(12));

    nm_iam_state_add_user(state, admin);

    nm_iam_state_set_password_open_password(state, random_password(12));
    nm_iam_state_set_password_open_sct(state, random_password(12));

    nm_iam_state_set_initial_pairing_username(state, initialUsername);
    nm_iam_state_set_open_pairing_role(state, "Guest");
    nm_iam_state_set_password_invite_pairing(state, true);
    nm_iam_state_set_friendly_name(state, "Tcp Tunnel");

    return save_tcp_tunnel_state(file, state);
}

bool createService(cJSON* root)
{
    char id[20];
    char host[20];
    uint16_t port;
    printf("Service ID (max 20 characters): ");
    if (scanf("%20s", id) != 1) {
        char i=0;
        while (i != '\n') { (void)scanf("%c", &i); }
        printf("Service creation failed. Invalid service ID entered." NEWLINE);
        return false;
    }

    printf("Service Host (max 20 characters) (e.g. 127.0.0.1): ");
    if (scanf("%20s", host) != 1) {
        char i=0;
        while (i != '\n') { (void)scanf("%c", &i); }
        printf("Service creation failed. Invalid service host entered." NEWLINE);
        return false;
    }

    printf("Service Port: ");
    if (scanf("%hu", &port) != 1) {
        char i=0;
        while (i != '\n') { (void)scanf("%c", &i); }
        printf("Service creation failed. Invalid service port entered." NEWLINE);
        return false;
    }

    struct tcp_tunnel_service* service = tcp_tunnel_service_new();

    service->id = strdup(id);
    service->type = strdup(id);
    service->host = strdup(host);
    service->port = port;

    printf("Service metadata is a map of strings to strings that a client can retrieve using COAP." NEWLINE);
    printf("Do you want to add metadata to this service? ");
    bool createMetadata = yes_no();
    while (createMetadata)
    {
        char key[20] = {0};
        char value[20] = {0};

        printf("Metadata entry key: ");
        if (scanf("%20s", key) != 1) {
            char i=0;
            while (i != '\n') { (void)scanf("%c", &i); }
            printf("Service creation failed. Invalid metadata key entered." NEWLINE);
            return false;
        }

        printf("Metadata entry value: ");
        if (scanf("%20s", value) != 1) {
            char i=0;
            while (i != '\n') { (void)scanf("%c", &i); }
            printf("Service creation failed. Invalid metadata value entered." NEWLINE);
            return false;
        }

        nn_string_map_insert(&service->metadata, key, value);

        printf("Do you want to add another key-value pair? ");
        createMetadata = yes_no();
    }

    cJSON_AddItemToArray(root, tcp_tunnel_service_as_json(service));
    tcp_tunnel_service_free(service);
    return true;
}

bool create_services_interactive(const char* file)
{
    printf("The default service configuration enables SSH to 127.0.0.1:22" NEWLINE);
    printf("Do you want to create a custom services configuration? ");
    bool createCustom = yes_no();
    if (createCustom) {
        printf("Each TCP Tunnel Service requires a unique ID and the host and port the service should connect to" NEWLINE);
        cJSON* root = cJSON_CreateArray();
        bool makeService = true;
        do {
            createService(root);
            printf("Do you want to add another service? ");
            makeService = yes_no();
        } while (makeService);
        return json_config_save(file, root);
    } else {
        printf("Use default services" NEWLINE);
        return tcp_tunnel_create_default_services_file(file);
    }
}
