#include "tcp_tunnel.h"
#include "iam_config.h"
#include "tcp_tunnel_services.h"
#include "tcp_tunnel_state.h"
#include <apps/common/device_config.h>
#include <apps/common/json_config.h>
#include <apps/common/prompt_stdin.h>
#include <apps/common/random_string.h>
#include <apps/common/string_file.h>
#include <modules/iam/nm_iam_serializer.h>
#include <modules/iam/nm_iam_state.h>

#include <cjson/cJSON.h>
#include <stdio.h>

#if defined(_WIN32)
#define NEWLINE "\r\n"
#else
#define NEWLINE "\n"
#endif

#define DEFAULT_FRIENDLY_NAME "Tcp Tunnel"

bool create_state_interactive(struct nm_fs* fsImpl, const char* file);
bool create_state_interactive_custom(struct nm_fs* fsImpl, const char* file);
bool create_state_default(struct nm_fs* fsImpl, const char* file);
bool create_services_interactive(struct nm_fs* fsImpl, const char* file);

static bool prompt_create_device_config(struct tcp_tunnel* tcpTunnel)
{
    if (string_file_exists(&tcpTunnel->fsImpl, tcpTunnel->deviceConfigFile)) {

        printf("Not creating a new Product ID and Device ID configuration since they have already been configured in (%s)." NEWLINE, tcpTunnel->deviceConfigFile);
    } else {
        printf("No device configuration found. Creating configuration: %s." NEWLINE, tcpTunnel->deviceConfigFile);
        if (!create_device_config_interactive(&tcpTunnel->fsImpl, tcpTunnel->deviceConfigFile)) {
            return false;
        }
    }
    printf(NEWLINE);
    return true;
}

bool tcp_tunnel_config_interactive(struct tcp_tunnel* tcpTunnel) {
    bool createDeviceConfigSuccess = prompt_create_device_config(tcpTunnel);
    if (!createDeviceConfigSuccess) {
        return false;
    }

    bool createIamConfig = false;
    if (string_file_exists(&tcpTunnel->fsImpl, tcpTunnel->iamConfigFile)) {
        printf("The IAM configuration already exists (%s)" NEWLINE, tcpTunnel->iamConfigFile);
        createIamConfig = prompt_yes_no("Do you want to recreate it?");
    } else {
        printf("No IAM configuration found. Creating configuration: %s" NEWLINE, tcpTunnel->iamConfigFile);
        createIamConfig = true;
    }

    if (createIamConfig) {
        if (!iam_config_create_default(&tcpTunnel->fsImpl, tcpTunnel->iamConfigFile)) {
            printf("The IAM configuration file %s could not be created." NEWLINE, tcpTunnel->iamConfigFile);
            return false;
        }
    }
    printf(NEWLINE);

    bool createIamState = false;

    if (string_file_exists(&tcpTunnel->fsImpl, tcpTunnel->stateFile)) {
        printf("The IAM State already exists (%s)" NEWLINE, tcpTunnel->stateFile);
        createIamState = prompt_yes_no("Do you want to recreate it?");
    } else {
        printf("No IAM state file found. Creating IAM state file: %s" NEWLINE, tcpTunnel->stateFile);
        createIamState = true;
    }
    if (createIamState) {
        if (!create_state_interactive(&tcpTunnel->fsImpl, tcpTunnel->stateFile)) {
            printf("Could not create the IAM state %s" NEWLINE, tcpTunnel->stateFile);
            return false;
        }
    }
    printf(NEWLINE);

    bool createServices = false;

    if (string_file_exists(&tcpTunnel->fsImpl, tcpTunnel->servicesFile)) {
        printf("The Tunnel Services configuration already exists (%s)" NEWLINE, tcpTunnel->servicesFile);
        createServices = prompt_yes_no("Do you want to recreate it?");
    } else {
        printf("No Tunnel Services configuration found. Creating configuration file: %s" NEWLINE, tcpTunnel->stateFile);
        createServices = true;
    }
    if (createServices) {
        if (!create_services_interactive(&tcpTunnel->fsImpl, tcpTunnel->servicesFile)) {
            printf("Could not create the service configuration %s" NEWLINE, tcpTunnel->servicesFile);
            return false;
        }
    }
    printf(NEWLINE);

    return true;
}

bool create_state_interactive(struct nm_fs* fsImpl, const char* file)
{
    printf("The IAM State enables pairing modes, and determines what role to assign new users." NEWLINE);
    bool createCustomIam = prompt_yes_no("Do you want to create a custom IAM State?");
    if (createCustomIam) {
        printf("Creating custom iam configuration" NEWLINE);
        return create_state_interactive_custom(fsImpl, file);
    }
    printf("Use default iam" NEWLINE);
    return create_state_default(fsImpl, file);
}

// NOLINTNEXTLINE(misc-no-recursion) recursion is ok since it only happens during interactive setup.
bool create_state_interactive_custom(struct nm_fs* fsImpl, const char* file) {
    const char* roles[] = {"Unpaired", "Guest", "Standard", "Administrator"};
    bool enableLocalInitialPairing = 0;
    bool enableLocalOpenPairing = 0;
    bool enablePasswordInvitePairing = 0;
    bool enablePasswordOpenPairing = 0;
    uint8_t pickedRole = 1; // Default = Guest

    enableLocalInitialPairing = prompt_yes_no("Enable Local Initial Pairing");
    enableLocalOpenPairing = prompt_yes_no("Enable Local Open Pairing");
    enablePasswordInvitePairing = prompt_yes_no("Enable Password Invite Pairing");
    enablePasswordOpenPairing = prompt_yes_no("Enable Password Open Pairing");

    printf(NEWLINE);
    if (!enableLocalInitialPairing && !enablePasswordInvitePairing) {
        printf("Both Local Initial Pairing and Password Invite Pairing modes are disabled. This means it will not be possible to create an Administrator of this device." NEWLINE);
        printf("If IAM management is not needed, this is perfectly fine." NEWLINE);
        if (!prompt_yes_no("Is it ok not to be able to create an Administrator?")) {
            return create_state_interactive_custom(fsImpl, file);
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
    pickedRole = (uint8_t)prompt_uint16(NULL, 3);

    struct nm_iam_state* state = nm_iam_state_new();

    {
        char friendlyName[64];
        int friendlyNameMax = ARRAY_SIZE(friendlyName);
        prompt("Enter a friendly name for your device (max %i characters, empty string will default to \"%s\")",
               friendlyName, friendlyNameMax, friendlyNameMax, DEFAULT_FRIENDLY_NAME);
        if (friendlyName[0] == 0) {
            nm_iam_state_set_friendly_name(state, DEFAULT_FRIENDLY_NAME);
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

    return save_tcp_tunnel_state(fsImpl, file, state);

}

bool create_state_default(struct nm_fs* fsImpl, const char* file)
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

    return save_tcp_tunnel_state(fsImpl, file, state);
}

bool createService(cJSON* root)
{
    char id[20] = {0};
    char host[20] = {0};
    uint16_t port = 0;

    prompt_repeating("Service ID (max 20 characters)", id, ARRAY_SIZE(id));
    prompt_repeating("Service Host (max 20 characters)", host, ARRAY_SIZE(host));
    port = prompt_uint16("Service Port", 0xffff);

    struct tcp_tunnel_service* service = tcp_tunnel_service_new();

    service->id = strdup(id);
    service->type = strdup(id);
    service->host = strdup(host);
    service->port = port;

    printf("Service metadata is a map of strings to strings that a client can retrieve using COAP." NEWLINE);
    bool createMetadata = prompt_yes_no("Do you want to add metadata to this service?");
    while (createMetadata)
    {
        char key[20] = {0};
        char value[20] = {0};

        prompt_repeating("Metadata entry key", key, ARRAY_SIZE(key));
        prompt_repeating("Metadata entry value", value, ARRAY_SIZE(value));

        nn_string_map_insert(&service->metadata, key, value);

        createMetadata = prompt_yes_no("Do you want to add another key-value pair?");
    }

    cJSON_AddItemToArray(root, tcp_tunnel_service_as_json(service));
    tcp_tunnel_service_free(service);
    return true;
}

bool create_services_interactive(struct nm_fs* fsImpl, const char* file)
{
    printf("The default service configuration enables SSH to 127.0.0.1:22" NEWLINE);
    bool createCustom = prompt_yes_no("Do you want to create a custom services configuration?");
    if (createCustom) {
        printf("Each TCP Tunnel Service requires a unique ID and the host and port the service should connect to" NEWLINE);
        cJSON* root = cJSON_CreateArray();
        bool makeService = true;
        do {
            createService(root);
            makeService = prompt_yes_no("Do you want to add another service?");
        } while (makeService);
        return json_config_save(fsImpl, file, root);
    }
    printf("Use default services" NEWLINE);
    return tcp_tunnel_create_default_services_file(fsImpl, file);
}

bool tcp_tunnel_demo_config(struct tcp_tunnel* tcpTunnel)
{
    bool createDeviceConfigSuccess = prompt_create_device_config(tcpTunnel);
    if (!createDeviceConfigSuccess) {
        return false;
    }

    bool createConfig = true;
    if (string_file_exists(&tcpTunnel->fsImpl, tcpTunnel->iamConfigFile) ||
        string_file_exists(&tcpTunnel->fsImpl, tcpTunnel->stateFile) ||
        string_file_exists(&tcpTunnel->fsImpl, tcpTunnel->servicesFile))
    {
        createConfig = prompt_yes_no_default("Overwrite Existing TCP Tunnel State and Configuration?", true);
    }
    if (!createConfig) {
        printf("Not creating a new configuration." NEWLINE);
        exit(1);
    }


    if (!iam_config_create_default(&tcpTunnel->fsImpl, tcpTunnel->iamConfigFile)) {
        printf("The IAM configuration file %s could not be created." NEWLINE,
               tcpTunnel->iamConfigFile);
        return false;
    }
    printf(NEWLINE);

    {
        printf(
            "Demo initialization will make a simple IAM setup, be aware that this is not what you want in production." NEWLINE
            "'Local Open Pairing' and 'Password Open Pairing' are enabled. Newly paired users get the 'Administrator' role." NEWLINE NEWLINE
        );

        struct nm_iam_state* state = nm_iam_state_new();
        nm_iam_state_set_friendly_name(state, DEFAULT_FRIENDLY_NAME);

        nm_iam_state_set_password_open_password(state, random_password(12));
        nm_iam_state_set_password_open_sct(state, random_password(12));
        nm_iam_state_set_open_pairing_role(state, "Administrator");

        nm_iam_state_set_local_open_pairing(state, true);
        nm_iam_state_set_password_open_pairing(state, true);

        nm_iam_state_set_password_invite_pairing(state, false);
        nm_iam_state_set_local_initial_pairing(state, false);

        save_tcp_tunnel_state(&tcpTunnel->fsImpl, tcpTunnel->stateFile, state);
    }

    printf("Next step is to add TCP tunnel services." NEWLINE);

    cJSON* root = cJSON_CreateArray();

    size_t numServices = 0;

    while (true) {
        printf(
            "What type of service do you want to add?" NEWLINE
            "[0]: continue (when you are done adding services)" NEWLINE
            "[1]: ssh" NEWLINE
            "[2]: http" NEWLINE
            "[3]: rtsp" NEWLINE
        );

        const char* message = "Enter a valid number";
        uint8_t choice = 0;
        if (numServices == 0) {
            choice = (uint8_t)prompt_uint16_default(message, 3, 1);
        } else {
            choice = (uint8_t)prompt_uint16_default(message, 3, 0);
        }


        enum {
            CHOICE_EXIT = 0,
            CHOICE_SSH  = 1,
            CHOICE_HTTP = 2,
            CHOICE_RTSP = 3
        };

        if (choice == CHOICE_EXIT) {
            break;
        }

        struct tcp_tunnel_service* service = tcp_tunnel_service_new();

        service->host = strdup("127.0.0.1");

        switch (choice) {
            case CHOICE_SSH: {
                service->id = strdup("ssh");
                service->type = strdup("ssh");
                service->port = prompt_uint16_default("Enter your SSH port", 0xffff, 22);
                printf("Added ssh service on localhost port %i" NEWLINE, service->port);
                break;
            }

            case CHOICE_HTTP: {
                service->id = strdup("http");
                service->type = strdup("http");
                service->port = prompt_uint16_default("Enter the port of your HTTP server", 0xffff, 80);
                printf("Added http service on localhost port %i" NEWLINE, service->port);
                break;
            }

            case CHOICE_RTSP: {
                service->id = strdup("rtsp");
                service->type = strdup("rtsp");
                service->port = prompt_uint16_default("Enter the port of your RTSP server", 0xffff, 8554);

                const char* key = "rtsp-path";
                char value[64] = {0};

                const char* endpoint = "/video";
                prompt("Enter your RTSP endpoint (default: %s)", value, ARRAY_SIZE(value), endpoint);
                if (value[0] != 0) {
                    endpoint = value;
                }
                nn_string_map_insert(&service->metadata, key, endpoint);

                printf("Added rtsp service on localhost port %i with metadata rtsp-path => %s" NEWLINE, service->port, endpoint);
                break;
            }
            default: break;
        }

        cJSON_AddItemToArray(root, tcp_tunnel_service_as_json(service));
        tcp_tunnel_service_free(service);
        numServices++;
        printf(NEWLINE);
    }

    printf(NEWLINE);
    json_config_save(&tcpTunnel->fsImpl, tcpTunnel->servicesFile, root);

    if (numServices == 0) {
        printf("WARNING: No TCP Tunnel services was added. You will not be able to Tunnel any TCP traffic." NEWLINE);
    }

    return true;
}
