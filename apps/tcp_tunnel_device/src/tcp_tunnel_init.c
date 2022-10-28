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
#include <ctype.h>

#if defined(_WIN32)
#define NEWLINE "\r\n"
#else
#define NEWLINE "\n"
#endif

#define ARRAY_SIZE(array) (sizeof(array)/sizeof((array)[0]))
#define DEFAULT_FRIENDLY_NAME "Tcp Tunnel"

bool create_device_config_interactive(const char* file);
bool create_state_interactive(const char* file);
bool create_state_interactive_custom(const char* file);
bool create_state_default(const char* file);
bool create_services_interactive(const char* file);

static void to_lowercase(char* buffer, size_t size)
{
    for (int i = 0; i < size && buffer[i] != 0; i++) {
        buffer[i] = tolower(buffer[i]);
    }
}

static bool str_is_numerical(char* buffer, size_t size)
{
    for (int i = 0; i < size && buffer[i] != 0; i++) {
        char c = buffer[i];
        if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

static inline bool is_printable(char c)
{
    return c >= 0x20 && c <= 0x7e;
}

// returns true if user input is size <= (bufferSize-1)
static bool prompt(const char* msg, char* buffer, size_t bufferSize, ...) 
{
    char c;
    int i = 0;
    int n = bufferSize-1;

    va_list args;
    va_start(args, bufferSize);
    vprintf(msg, args);
    va_end(args);

    printf(": ");

    while ((c = getchar())) {
        if (c == '\n' || c == EOF) {
            int nullBytePosition = i < n ? i : n;
            buffer[nullBytePosition] = 0;
            return i <= n;
        }

        if (i < n && is_printable(c)) {
            buffer[i] = c;
        }
        i++;
    }
    return false;
}

// keeps prompting until a non-empty string is given
static bool prompt_repeating(const char* msg, char* buffer, size_t bufferSize)
{
    while (true) {
        bool ret = prompt(msg, buffer, bufferSize);
        if (buffer[0] != 0) {
            return ret;
        }
    }
}

static bool prompt_yes_no(const char* msg)
{
    while (true) {
        char buffer[4];
        char n = ARRAY_SIZE(buffer);

        bool valid;
        if (msg == NULL) {
            valid = prompt("[y/n]", buffer, n);
        } else {
            valid = prompt("%s [y/n]", buffer, n, msg);
        }

        if(!valid) {
            continue;
        }
        to_lowercase(buffer, n);

        if (strncmp(buffer, "y", n) == 0 || strncmp(buffer, "yes", n) == 0) {
            return true;
        }

        if (strncmp(buffer, "n", n) == 0 || strncmp(buffer, "no", n) == 0) {
            return false;
        }
    }
}

static uint16_t prompt_uint16(const char* msg, uint16_t max) {
    while (true) {
        char buffer[16] = {0};
        int n = ARRAY_SIZE(buffer);

        bool valid;
        if (msg == NULL) {
            valid = prompt("[0-%d]", buffer, n, max);
        } else {
            valid = prompt("%s [0-%d]", buffer, n, msg, max);
        }

        if(!valid) {
            continue;
        }

        if (buffer[0] == 0) {
            continue;
        }

        if (!str_is_numerical(buffer, n)) {
            continue;
        }

        long num = strtol(buffer, NULL, 10);
        if (num <= max) {
            return num;
        }
    }
}

static uint16_t prompt_uint16_default(const char* msg, uint16_t max, uint16_t def) {
    while (true) {
        char buffer[16] = {0};
        int n = ARRAY_SIZE(buffer);

        bool valid;
        if (msg == NULL) {
            valid = prompt("(default %i) [0-%d]", buffer, n, def, max);
        } else {
            valid = prompt("%s (default %i) [0-%d]", buffer, n, msg, def, max);
        }

        if(!valid) {
            continue;
        }

        if (buffer[0] == 0) {
            return def;
        }

        if (!str_is_numerical(buffer, n)) {
            continue;
        }

        long num = strtol(buffer, NULL, 10);
        if (num <= max) {
            return num;
        }
    }
}


static bool prompt_create_device_config(struct tcp_tunnel* tcpTunnel) 
{
    bool createDeviceConfig = false;
    if (string_file_exists(tcpTunnel->deviceConfigFile)) {
        printf("A device configuration already exists (%s)" NEWLINE, tcpTunnel->deviceConfigFile);
        createDeviceConfig = prompt_yes_no("Do you want to recreate it?");
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
    return true;
}

bool tcp_tunnel_config_interactive(struct tcp_tunnel* tcpTunnel) {
    bool createDeviceConfigSuccess = prompt_create_device_config(tcpTunnel);
    if (!createDeviceConfigSuccess) {
        return false;
    }

    bool createIamConfig = false;
    if (string_file_exists(tcpTunnel->iamConfigFile)) {
        printf("The IAM configuration already exists (%s)" NEWLINE, tcpTunnel->iamConfigFile);
        createIamConfig = prompt_yes_no("Do you want to recreate it?");
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
        printf("The IAM State already exists (%s)" NEWLINE, tcpTunnel->stateFile);
        createIamState = prompt_yes_no("Do you want to recreate it?");
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
        printf("The Tunnel Services configuration already exists (%s)" NEWLINE, tcpTunnel->servicesFile);
        createServices = prompt_yes_no("Do you want to recreate it?");
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
    prompt_repeating("Product Id", productId, ARRAY_SIZE(productId));
    prompt_repeating("Device Id", deviceId, ARRAY_SIZE(deviceId));

    struct device_config dc;
    memset(&dc, 0, sizeof(struct device_config));
    dc.productId = productId;
    dc.deviceId = deviceId;
    return save_device_config(file, &dc);
}

bool create_state_interactive(const char* file)
{
    printf("The IAM State enables pairing modes, and determines what role to assign new users." NEWLINE);
    bool createCustomIam = prompt_yes_no("Do you want to create a custom IAM State?");
    if (createCustomIam) {
        printf("Creating custom iam configuration" NEWLINE);
        return create_state_interactive_custom(file);
    } else {
        printf("Use default iam" NEWLINE);
        return create_state_default(file);
    }
}

bool create_state_interactive_custom(const char* file) {
    const char* roles[] = {"Unpaired", "Guest", "Standard", "Administrator"};
    bool enableLocalInitialPairing;
    bool enableLocalOpenPairing;
    bool enablePasswordInvitePairing;
    bool enablePasswordOpenPairing;
    uint8_t pickedRole = 1; // Default = Guest

    enableLocalInitialPairing = prompt_yes_no("Enable Local Initial Pairing");
    enableLocalOpenPairing = prompt_yes_no("Enable Local Open Pairing");
    enablePasswordInvitePairing = prompt_yes_no("Enable Password Invite Pairing");
    enablePasswordOpenPairing = prompt_yes_no("Enable Password Open Pairing");

    printf(NEWLINE);
    if (!enableLocalInitialPairing && !enablePasswordInvitePairing) {
        printf("Both Local Initial Pairing and Password Invite Pairing modes are disabled. This means it will not be possible to create an Administrator of this device." NEWLINE);
        printf("If IAM management is not needed, this is perfectly fine." NEWLINE);
        if (!prompt_yes_no("Continue with choices?")) {
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
    pickedRole = prompt_uint16(NULL, 3);

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
    char id[20] = {0};
    char host[20] = {0};
    uint16_t port;
    
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

bool create_services_interactive(const char* file)
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
        return json_config_save(file, root);
    } else {
        printf("Use default services" NEWLINE);
        return tcp_tunnel_create_default_services_file(file);
    }
}

bool tcp_tunnel_demo_config(struct tcp_tunnel* tcpTunnel)
{
    bool createDeviceConfigSuccess = prompt_create_device_config(tcpTunnel);
    if (!createDeviceConfigSuccess) {
        return false;
    }

    bool createIamConfig = false;
    if (string_file_exists(tcpTunnel->iamConfigFile)) {
        printf("The IAM configuration already exists (%s)" NEWLINE, tcpTunnel->iamConfigFile);
        createIamConfig = prompt_yes_no("Do you want to recreate it?");
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

    printf(
        "Demo initialization will make a simple IAM setup, be aware that this is not what you want in production." NEWLINE
        "Local Open Pairing and Password Open Pairing are enabled. Newly paired users get the Administrator role." NEWLINE NEWLINE
    );

    // default IAM state
    {
        struct nm_iam_state* state = nm_iam_state_new();
        nm_iam_state_set_friendly_name(state, DEFAULT_FRIENDLY_NAME);

        nm_iam_state_set_password_open_password(state, random_password(12));
        nm_iam_state_set_password_open_sct(state, random_password(12));
        nm_iam_state_set_open_pairing_role(state, "Administrator");

        nm_iam_state_set_local_open_pairing(state, true);
        nm_iam_state_set_password_open_pairing(state, true);

        nm_iam_state_set_password_invite_pairing(state, false);
        nm_iam_state_set_local_initial_pairing(state, false);

        save_tcp_tunnel_state(tcpTunnel->stateFile, state);
    }

    if (string_file_exists(tcpTunnel->servicesFile)) {
        printf("The Tunnel Services configuration already exists (%s)" NEWLINE, tcpTunnel->servicesFile);
        bool yn = prompt_yes_no("Do you want to recreate it?");
        printf(NEWLINE);
        if(!yn) {
            return true;
        }
    }


    printf("Next step is to add TCP tunnel services.");

    cJSON* root = cJSON_CreateArray();

    while (true) {
        printf(
            NEWLINE
            "What type of service do you want to add?" NEWLINE
            "[1]: ssh" NEWLINE
            "[2]: http" NEWLINE
            "[3]: rtsp" NEWLINE
        );
        uint8_t choice = prompt_uint16("Enter a valid number (0 to exit)", 3);
        

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
                break;
            }

            case CHOICE_HTTP: {
                service->id = strdup("http");
                service->type = strdup("http");
                service->port = prompt_uint16_default("Enter the port of your HTTP server", 0xffff, 80);
                break;
            }

            case CHOICE_RTSP: {
                service->id = strdup("rtsp");
                service->type = strdup("rtsp");
                service->port = prompt_uint16_default("Enter the port of your RTSP server", 0xffff, 8554);

                const char* key = "rtsp-path";
                char value[20] = {0};

                prompt_repeating("Enter your RTSP endpoint (e.g. /video)", value, ARRAY_SIZE(value));

                nn_string_map_insert(&service->metadata, key, value);

                break;
            }
        }

        printf("Added service of type \"%s\" on localhost port %i" NEWLINE, service->type, service->port);
        cJSON_AddItemToArray(root, tcp_tunnel_service_as_json(service));
        tcp_tunnel_service_free(service);
    }

    json_config_save(tcpTunnel->servicesFile, root);
    return true;
}
