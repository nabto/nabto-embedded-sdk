#include "tcp_tunnel.h"
#include "iam_config.h"
#include "tcp_tunnel_state.h"
#include <apps/common/string_file.h>
#include <apps/common/device_config.h>
#include <modules/iam/nm_iam_state.h>
#include <apps/common/random_string.h>
#include <modules/iam/nm_iam_serializer.h>

#include <stdio.h>
#include <string.h>

bool create_device_config_interactive(const char* file);
bool create_state_interactive(const char* file);
bool create_state_interactive_custom(const char* file);
bool create_state_default(const char* file);

bool yes_no();

bool tcp_tunnel_config_interactive(struct tcp_tunnel* tcpTunnel) {
    bool createDeviceConfig = false;
    if (string_file_exists(tcpTunnel->deviceConfigFile)) {
        printf("The device configuration %s already exists do you want to recreate it? ", tcpTunnel->deviceConfigFile);
        createDeviceConfig = yes_no();
    } else {
        printf("The device configuration %s does not exist. Creating a new config.\n", tcpTunnel->deviceConfigFile);
        createDeviceConfig = true;
    }
    if (createDeviceConfig) {
        if (!create_device_config_interactive(tcpTunnel->deviceConfigFile)) {
            return false;
        }
    }

    bool createIamConfig = false;
    if (string_file_exists(tcpTunnel->iamConfigFile)) {
        printf("The IAM configuration %s already exists do you want to recreate it? ", tcpTunnel->iamConfigFile);
        createIamConfig = yes_no();
    } else {
        printf("The IAM configuration %s does not exist. Creating a new IAM configuration.\n", tcpTunnel->iamConfigFile);
        createIamConfig = true;
    }

    if (createIamConfig) {
        if (!iam_config_create_default(tcpTunnel->iamConfigFile)) {
            printf("The IAM configuration file %s could not be created.\n", tcpTunnel->iamConfigFile);
            return false;
        }
    }

    bool createIamState = false;

    if (string_file_exists(tcpTunnel->stateFile)) {
        printf("The IAM State %s already exists do you want to recreate it? ", tcpTunnel->stateFile);
        createIamState = yes_no();
    } else {
        printf("No IAM state file exists %s. Creating a new IAM state\n", tcpTunnel->stateFile);
        createIamState = true;
    }
    if (createIamState) {
        if (!create_state_interactive(tcpTunnel->stateFile)) {
            printf("Could not create the IAM default state %s\n", tcpTunnel->stateFile);
            return false;
        }
    }

    return true;
}

bool create_device_config_interactive(const char* file) {
    char productId[20];
    char deviceId[20];
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
    printf("Do you want to create a custom IAM State? ");
    bool createCustomIam = yes_no();
    if (createCustomIam) {
        printf("Creating custom iam configuration\n");
        return create_state_interactive_custom(file);
    } else {
        printf("Use default iam\n");
        return create_state_default(file);
    }
    return false;
}

bool create_state_interactive_custom(const char* file) {
    bool enableLocalInitialPairing;
    bool enableLocalOpenPairing;
    bool enablePasswordInvitePairing;
    bool enablePasswordOpenPairing;

    printf("Enable Local Initial Pairing: ");
    enableLocalInitialPairing = yes_no();
    printf("Enable Local Open Pairing: ");
    enableLocalOpenPairing = yes_no();
    printf("Enable Password Invite Pairing: ");
    enablePasswordInvitePairing = yes_no();
    printf("Enable Password Open Pairing: ");
    enablePasswordOpenPairing = yes_no();

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

    return save_tcp_tunnel_state(file, state);
}
