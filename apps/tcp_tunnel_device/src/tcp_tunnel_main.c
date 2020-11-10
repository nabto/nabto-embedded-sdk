#include "iam_config.h"
#include "help.h"
#include "tcp_tunnel.h"
#include "tcp_tunnel_state.h"
#include "tcp_tunnel_services.h"
#include "device_event_handler.h"


#include <nabto/nabto_device.h>
#include <apps/common/device_config.h>
#include <apps/common/private_key.h>
#include <apps/common/logging.h>
#include <apps/common/string_file.h>

#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_user.h>

#include <nn/string_set.h>

#include <nn/log.h>


#include <gopt/gopt.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#include <stdbool.h>

#include <sys/stat.h>
#include <sys/types.h>

#if defined(_WIN32)
#define HOMEDIR_ENV_VARIABLE "APPDATA"
#define HOMEDIR_NABTO_FOLDER "nabto"
#define NEWLINE "\r\n"
#else
#define HOMEDIR_ENV_VARIABLE "HOME"
#define HOMEDIR_NABTO_FOLDER ".nabto"
#define NEWLINE "\n"
#endif

#define HOMEDIR_EDGE_FOLDER HOMEDIR_NABTO_FOLDER "/edge"

const char* DEVICE_CONFIG_FILE = "config/device.json";
const char* TCP_TUNNEL_STATE_FILE = "state/tcp_tunnel_device_iam_state.json";
const char* TCP_TUNNEL_IAM_FILE = "config/tcp_tunnel_device_iam_config.json";
const char* TCP_TUNNEL_SERVICES_FILE = "config/tcp_tunnel_device_services.json";
const char* DEVICE_KEY_FILE = "keys/device.key";

enum {
    OPTION_HELP = 1,
    OPTION_VERSION,
    OPTION_LOG_LEVEL,
    OPTION_SHOW_STATE,
    OPTION_HOME_DIR,
    OPTION_RANDOM_PORTS,
    OPTION_RESET,
    OPTION_INIT
};

struct args {
    bool showHelp;
    bool showVersion;
    bool showState;
    const char* logLevel;
    char* homeDir;
    bool randomPorts;
    bool reset;
    bool init;
};

NabtoDevice* device_;

static void signal_handler(int s);

static void print_iam_state(struct nm_iam_state* state);
static void iam_user_changed(struct nm_iam* iam, void* userData);
static bool make_directory(const char* directory);



void print_version()
{
    printf("TCP Tunnel Device Version: %s" NEWLINE, nabto_device_version());
}

void print_device_config_load_failed(const char* fileName)
{
    printf("Could not open or parse the device config file (%s)." NEWLINE, fileName);
    printf("Please ensure the file exists and has the following format." NEWLINE);
    printf("The Server and ServerPort fields are optional." NEWLINE);
    printf("{" NEWLINE);
    printf("  \"ProductId\": \"pr-abcd1234\"," NEWLINE);
    printf("  \"DeviceId\": \"de-abcd1234\"," NEWLINE);
    printf("  \"Server\": \"pr-abcd1234.devices.nabto.net or pr-abcd1234.devices.dev.nabto.net or something else.\"," NEWLINE);
    printf("  \"ServerPort\": \"443\"," NEWLINE);
    printf("}" NEWLINE);
}

void print_iam_config_load_failed(const char* fileName)
{
    printf("Could not open or parse IAM config file (%s)" NEWLINE, fileName);
}

void print_tcp_tunnel_state_load_failed(const char* fileName)
{
    printf("Could not load TCP tunnel state file (%s)" NEWLINE, fileName);
}

void print_start_text(struct args* args)
{
    printf("TCP Tunnel Device" NEWLINE);
}

void print_private_key_file_load_failed(const char* fileName)
{
    printf("Could not load the private key (%s) see error log for further details." NEWLINE, fileName);
}

bool check_log_level(const char* level)
{
    if (strcmp(level, "error") == 0 ||
        strcmp(level, "warn") == 0 ||
        strcmp(level, "info") == 0 ||
        strcmp(level, "trace") == 0)
    {
        return true;
    }
    return false;
}

static bool parse_args(int argc, char** argv, struct args* args)
{
    const char x1s[] = "h";      const char* x1l[] = { "help", 0 };
    const char x2s[] = "v";      const char* x2l[] = { "version", 0 };
    const char x3s[] = "";       const char* x3l[] = { "log-level", 0 };
    const char x4s[] = "";       const char* x4l[] = { "show-state", 0 };
    const char x5s[] = "H";      const char* x5l[] = { "home-dir", 0 };
    const char x6s[] = "";       const char* x6l[] = { "random-ports", 0 };
    const char x7s[] = "";       const char* x7l[] = { "reset", 0 };
    const char x8s[] = "";       const char* x8l[] = { "init", 0 };

    const struct { int k; int f; const char *s; const char*const* l; } opts[] = {
        { OPTION_HELP, GOPT_NOARG, x1s, x1l },
        { OPTION_VERSION, GOPT_NOARG, x2s, x2l },
        { OPTION_LOG_LEVEL, GOPT_ARG, x3s, x3l },
        { OPTION_SHOW_STATE, GOPT_NOARG, x4s, x4l },
        { OPTION_HOME_DIR, GOPT_ARG, x5s, x5l },
        { OPTION_RANDOM_PORTS, GOPT_NOARG, x6s, x6l },
        { OPTION_RESET, GOPT_NOARG, x7s, x7l },
        { OPTION_INIT, GOPT_NOARG, x8s, x8l },
        {0,0,0,0}
    };

    void *options = gopt_sort( & argc, (const char**)argv, opts);

    if (gopt(options, OPTION_HELP)) {
        args->showHelp = true;
    }
    if (gopt(options, OPTION_VERSION)) {
        args->showVersion = true;
    }
    if (gopt(options, OPTION_SHOW_STATE)) {
        args->showState = true;
    }

    if (gopt(options, OPTION_RANDOM_PORTS)) {
        args->randomPorts = true;
    }

    if (gopt(options, OPTION_RESET)) {
        args->reset = true;
    }

    if (gopt(options, OPTION_INIT)) {
        args->init = true;
    }

    if (gopt_arg(options, OPTION_LOG_LEVEL, &args->logLevel)) {

    } else {
        args->logLevel = "error";
    }

    if (!check_log_level(args->logLevel)) {
        printf("The log level %s is not valid" NEWLINE, args->logLevel);
    }

    const char* hd = NULL;
    if (gopt_arg(options, OPTION_HOME_DIR, &hd)) {
        args->homeDir = strdup(hd);
    }


    gopt_free(options);
    return true;
}

void args_init(struct args* args)
{
    memset(args, 0, sizeof(struct args));
}

void args_deinit(struct args* args)
{
    free(args->homeDir);
}

void tcp_tunnel_init(struct tcp_tunnel* tunnel)
{
    memset(tunnel, 0, sizeof(struct tcp_tunnel));
    nn_vector_init(&tunnel->services, sizeof(void*));
}

void tcp_tunnel_deinit(struct tcp_tunnel* tunnel)
{
    free(tunnel->deviceConfigFile);
    free(tunnel->stateFile);
    free(tunnel->iamConfigFile);
    free(tunnel->privateKeyFile);
    free(tunnel->servicesFile);
    free(tunnel->pairingPassword);
    free(tunnel->pairingServerConnectToken);
    struct tcp_tunnel_service* service;
    NN_VECTOR_FOREACH(&service, &tunnel->services)
    {
        tcp_tunnel_service_free(service);
    }
    nn_vector_deinit(&tunnel->services);
}

char* expand_file_name(const char* homeDir, const char* fileName)
{
    //homeDir+/+fileName+NULL
    size_t requiredLength = strlen(homeDir) + 1 + strlen(fileName) + 1;

    char* fullFileName = calloc(1,requiredLength);
    if (fullFileName == NULL) {
        return NULL;
    }

    sprintf(fullFileName, "%s/%s", homeDir, fileName);
    return fullFileName;
}

char* generate_pairing_string(const char* productId, const char* deviceId, const char* pairingPassword, const char* pairingServerConnectToken)
{
    static char buffer[1024];
    sprintf(buffer, "p=%s,d=%s,pwd=%s,sct=%s",
            productId,
            deviceId,
            pairingPassword,
            pairingServerConnectToken);
    return buffer;
}

void print_item(const char* item)
{
    size_t printSize = strlen(item);
    if (printSize > 16) {
        printSize = 16;
    }
    printf("%.*s", (int)printSize, item);

    const char* spaces = "                 ";
    size_t spacesSize = 17 - printSize;
    printf("%.*s", (int)spacesSize, spaces);
}

bool handle_main(struct args* args, struct tcp_tunnel* tunnel);

int main(int argc, char** argv)
{
    struct args args;
    args_init(&args);
    if (!parse_args(argc, argv, &args)) {
        printf("Could not parse arguments.");
        print_help();
        args_deinit(&args);
        return 1;
    }



    struct tcp_tunnel tunnel;
    tcp_tunnel_init(&tunnel);

    bool status = handle_main(&args, &tunnel);

    tcp_tunnel_deinit(&tunnel);
    args_deinit(&args);

    if (status) {
        return 0;
    } else {
        return 1;
    }
}

bool handle_main(struct args* args, struct tcp_tunnel* tunnel)
{
    if (args->showHelp) {
        print_help();
        return true;
    } else if (args->showVersion) {
        print_version();
        return true;
    }

    const char* homeEnv = getenv(HOMEDIR_ENV_VARIABLE);
    if (args->homeDir != NULL) {
        // perfect just using the homeDir
        make_directory(args->homeDir);
    } else if (homeEnv != NULL) {
        args->homeDir = expand_file_name(homeEnv, HOMEDIR_EDGE_FOLDER);
        char* dotNabto = expand_file_name(homeEnv, HOMEDIR_NABTO_FOLDER);
        make_directory(dotNabto);
        free(dotNabto);

        make_directory(args->homeDir);
    } else {
        printf("Missing HomeDir option or HOME environment variable one of these needs to be set." NEWLINE);
        return false;
    }

    NabtoDevice* device = nabto_device_new();
    struct nn_log logger;
    logging_init(device, &logger, args->logLevel);

    // Create directories if missing
    char* stateDir = expand_file_name(args->homeDir, "state");
    make_directory(stateDir);
    free(stateDir);

    char* keysDir = expand_file_name(args->homeDir, "keys");
    make_directory(keysDir);
    free(keysDir);

    char* configDir = expand_file_name(args->homeDir, "config");
    make_directory(configDir);
    free(configDir);

    tunnel->deviceConfigFile = expand_file_name(args->homeDir, DEVICE_CONFIG_FILE);
    tunnel->stateFile = expand_file_name(args->homeDir, TCP_TUNNEL_STATE_FILE);
    tunnel->iamConfigFile = expand_file_name(args->homeDir, TCP_TUNNEL_IAM_FILE);
    tunnel->servicesFile = expand_file_name(args->homeDir, TCP_TUNNEL_SERVICES_FILE);
    tunnel->privateKeyFile = expand_file_name(args->homeDir, DEVICE_KEY_FILE);

    if (args->init) {
        if (!tcp_tunnel_config_interactive(tunnel)) {
            printf("Init of the configuration and state failed" NEWLINE);
            return false;
        } else {
            printf("The configuration and state has been initialized" NEWLINE);
            return true;
        }
    } else {
        // check that all files exists
        if (!string_file_exists(tunnel->deviceConfigFile)) {
            printf("Missing device config %s, initialize it with --init" NEWLINE, tunnel->deviceConfigFile);
            return false;
        }

        if(!string_file_exists(tunnel->iamConfigFile)) {
            printf("Missing IAM configuration file %s, create it with --init" NEWLINE, tunnel->iamConfigFile);
            return false;
        }

        if (!string_file_exists(tunnel->stateFile)) {
            printf("Missing IAM state file %s, create it with --init" NEWLINE, tunnel->stateFile);
            return false;
        }
    }

    /**
     * Load data files
     */
    struct device_config dc;
    device_config_init(&dc);

    if (!load_device_config(tunnel->deviceConfigFile, &dc, &logger)) {
        printf("Failed to start device because a valid `%s` configuration file is missing. see --help for information about this file." NEWLINE, tunnel->deviceConfigFile);
        return false;
    }

    struct nm_iam_configuration* iamConfig = nm_iam_configuration_new();

    if (!iam_config_load(iamConfig, tunnel->iamConfigFile, &logger)) {
        print_iam_config_load_failed(tunnel->iamConfigFile);
        return false;
    }

    struct nm_iam_state* tcpTunnelState = nm_iam_state_new();

    if (!load_tcp_tunnel_state(tcpTunnelState, tunnel->stateFile, &logger)) {
        print_tcp_tunnel_state_load_failed(tunnel->stateFile);
        return false;
    }

    if (!load_tcp_tunnel_services(&tunnel->services, tunnel->servicesFile, &logger))
    {
        printf("Failed to load TCP Services from (%s)" NEWLINE, tunnel->servicesFile);
        return false;
    }

    if (!load_or_create_private_key(device, tunnel->privateKeyFile, &logger)) {
        print_private_key_file_load_failed(tunnel->privateKeyFile);
        return false;
    }

    nabto_device_set_product_id(device, dc.productId);
    nabto_device_set_device_id(device, dc.deviceId);
    if (dc.server != NULL) {
        nabto_device_set_server_url(device, dc.server);
    }
    if (dc.serverPort != 0) {
        nabto_device_set_server_port(device, dc.serverPort);
    }
    nabto_device_disable_remote_access(device);
    nabto_device_enable_mdns(device);
    nabto_device_mdns_add_subtype(device, "tcptunnel");
    nabto_device_mdns_add_txt_item(device, "fn", "tcp tunnel");


    struct nm_iam iam;
    nm_iam_init(&iam, device, &logger);

    if(!nm_iam_load_configuration(&iam, iamConfig)) {
        printf("Could not load iam configuration" NEWLINE);
        return false;
    }
    nm_iam_load_state(&iam, tcpTunnelState);


    struct tcp_tunnel_service* service;
    NN_VECTOR_FOREACH(&service, &tunnel->services)
    {
        nabto_device_add_tcp_tunnel_service(device, service->id, service->type, service->host, service->port);
    }

    char* deviceFingerprint;
    nabto_device_get_device_fingerprint(device, &deviceFingerprint);

    if (args->randomPorts) {
        nabto_device_set_local_port(device, 0);
        nabto_device_set_p2p_port(device, 0);
    }

    printf("######## Nabto TCP Tunnel Device ########" NEWLINE);
    printf("# Product ID:        %s" NEWLINE, dc.productId);
    printf("# Device ID:         %s" NEWLINE, dc.deviceId);
    printf("# Fingerprint:       %s" NEWLINE, deviceFingerprint);
    printf("# Version:           %s" NEWLINE, nabto_device_version());
    if (!args->randomPorts) {
        printf("# Local UDP Port:    %d" NEWLINE, 5592);
    }

    struct nm_iam_user* initialUser;
    struct nm_iam_user* user = NULL;
    NN_LLIST_FOREACH(user, &iam.state->users) {
        if (user->username != NULL && strcmp(user->username, iam.state->initialPairingUsername) == 0) {
            initialUser = user;
            break;
        }
    }

    bool initialUserNeedPairing = initialUser && initialUser->fingerprint == NULL;

    if (iam.state->localInitialPairing && initialUserNeedPairing) {
        printf("# " NEWLINE);
        printf(" The device is not yet paired with the initial user. You can use Local Initial Pairing to get access." NEWLINE);
    }


    if (iam.state->passwordInvitePairing && initialUserNeedPairing)
    {
        printf("# " NEWLINE);
        printf("# The initial user has not been paired yet. You can pair with the device usign Password Invite Pairing." NEWLINE);
        printf("# Initial Pairing Usermame:  %s" NEWLINE, initialUser->username);
        if (initialUser->password != NULL) {
            printf("# Initial Pairing Password:  %s" NEWLINE, initialUser->password);
        }
        if (initialUser->serverConnectToken != NULL) {
            printf("# Initial Pairing SCT:       %s" NEWLINE, initialUser->serverConnectToken);
        }
        // format the pairing string over the next couple of lines
        printf("# Initial Pairing String:    p=%s,d=%s,u=%s", dc.productId, dc.deviceId, initialUser->username);
        if (initialUser->password != NULL) {
            printf(",pwd=%s",initialUser->password);
        }
        if (initialUser->serverConnectToken != NULL) {
            printf(",sct=%s", initialUser->serverConnectToken);
        }
        printf(NEWLINE);

    }

    if (!initialUserNeedPairing) {
        //  we are past the initial user being paired.
        if (iam.state->passwordInvitePairing)
        {
            printf("# " NEWLINE);
            printf("# The device provides Password Invite Pairing, contact the administrator to access." NEWLINE);
        }

        if (iam.state->localOpenPairing) {
            printf("# " NEWLINE);
            printf("# The device offers Local Open Pairing" NEWLINE);
        }


        if (iam.state->passwordOpenPairing && iam.state->globalPairingPassword != NULL && iam.state->globalSct != NULL) {
            printf("# " NEWLINE);
            printf("# The device has Password Open Pairing enabled" NEWLINE);
            printf("# Open Pairing Password:  %s" NEWLINE, iam.state->globalPairingPassword);
            printf("# Open Pairing SCT:       %s" NEWLINE, iam.state->globalSct);
            printf("# Open Pairing String:    p=%s,d=%s,pwd=%s,sct=%s" NEWLINE, dc.productId, dc.deviceId, iam.state->globalPairingPassword, iam.state->globalSct);
        }
    }

    printf("# " NEWLINE);
    printf("######## Configured TCP Services ########" NEWLINE);
    printf("# "); print_item("Id"); print_item("Type"); print_item("Host"); printf("Port" NEWLINE);
    struct tcp_tunnel_service* item;

    NN_VECTOR_FOREACH(&item, &tunnel->services)
    {
        printf("# "); print_item(item->id); print_item(item->type); print_item(item->host); printf("%d" NEWLINE, item->port);
    }
    printf("########" NEWLINE);

    nabto_device_string_free(deviceFingerprint);

    if (args->showState) {
        print_iam_state(tcpTunnelState);
    } else {
        struct device_event_handler eventHandler;

        device_event_handler_init(&eventHandler, device);

        nm_iam_set_state_changed_callback(&iam, iam_user_changed, tunnel);

        NabtoDeviceFuture* fut = nabto_device_future_new(device);
        nabto_device_start(device, fut);
        NabtoDeviceError ec = nabto_device_future_wait(fut);
        nabto_device_future_free(fut);
        if (ec != NABTO_DEVICE_EC_OK) {
            if (ec == NABTO_DEVICE_EC_ADDRESS_IN_USE) {
                printf("The device could not be started as one or more udp sockets" NEWLINE);
                printf("could not be bound to the specified ports. This is most likely" NEWLINE);
                printf("due to several devices running on the same machine. The problem" NEWLINE);
                printf("can be mitigated by using the --random-ports option, this option" NEWLINE);
                printf("does however limit the ability to use direct pairing based on ips." NEWLINE);
            } else {
                printf("Could not start the device %s" NEWLINE, nabto_device_error_get_message(ec));
            }
            return false;
        }

        device_ = device;

        // Wait for the user to press Ctrl-C
        signal(SIGINT, &signal_handler);

        // block until the NABTO_DEVICE_EVENT_CLOSED event is emitted.
        device_event_handler_blocking_listener(&eventHandler);

        nabto_device_stop(device);

        device_event_handler_deinit(&eventHandler);
    }

    nabto_device_stop(device);
    nm_iam_deinit(&iam);
    nabto_device_free(device);


    device_config_deinit(&dc);

    return true;
}

void signal_handler(int s)
{
    NabtoDeviceFuture* fut = nabto_device_future_new(device_);
    nabto_device_close(device_, fut);
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
}


void print_iam_state(struct nm_iam_state* state)
{
    struct nm_iam_user* user;
    NN_LLIST_FOREACH(user, &state->users)
    {
        printf("User: %s, fingerprint: %s" NEWLINE, user->username, user->fingerprint);
    }
}


void iam_user_changed(struct nm_iam* iam, void* userData)
{
    struct tcp_tunnel* tcpTunnel = userData;
    if (!save_tcp_tunnel_state(tcpTunnel->stateFile, iam->state)) {
        printf("Could not save tcp_tunnel state to %s", tcpTunnel->stateFile);
    }
}

bool make_directory(const char* directory)
{
    mkdir(directory, 0777);
    return true;
}
