#include "iam_config.h"
#include "help.h"
#include "tcp_tunnel_state.h"
#include "tcp_tunnel_services.h"
#include "device_event_handler.h"


#include <nabto/nabto_device.h>
#include <apps/common/device_config.h>
#include <apps/common/private_key.h>
#include <apps/common/logging.h>

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
const char* TCP_TUNNEL_STATE_FILE = "state/tcp_tunnel_state.json";
const char* TCP_TUNNEL_IAM_FILE = "config/tcp_tunnel_iam.json";
const char* TCP_TUNNEL_SERVICES_FILE = "config/tcp_tunnel_services.json";
const char* DEVICE_KEY_FILE = "keys/device.key";

enum {
    OPTION_HELP = 1,
    OPTION_VERSION,
    OPTION_LOG_LEVEL,
    OPTION_SHOW_STATE,
    OPTION_HOME_DIR
};

struct args {
    bool showHelp;
    bool showVersion;
    bool showState;
    const char* logLevel;
    char* homeDir;
};


struct tcp_tunnel {
    char* pairingPassword;
    char* pairingServerConnectToken;

    char* deviceConfigFile;
    char* stateFile;
    char* iamConfigFile;
    char* servicesFile;
    char* privateKeyFile;

    struct nn_vector services;
};

NabtoDevice* device_;

static void signal_handler(int s);

static void print_iam_state(struct nm_iam* iam);
static void iam_user_changed(struct nm_iam* iam, const char* id, void* userData);
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

    const struct { int k; int f; const char *s; const char*const* l; } opts[] = {
        { OPTION_HELP, GOPT_NOARG, x1s, x1l },
        { OPTION_VERSION, GOPT_NOARG, x2s, x2l },
        { OPTION_LOG_LEVEL, GOPT_ARG, x3s, x3l },
        { OPTION_SHOW_STATE, GOPT_NOARG, x4s, x4l },
        { OPTION_HOME_DIR, GOPT_ARG, x5s, x5l },
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

char* generate_pairing_url(const char* productId, const char* deviceId, const char* pairingPassword, const char* pairingServerConnectToken)
{
    char* buffer = calloc(1, 1024); // long enough!

    sprintf(buffer, "https://tcp-tunnel.nabto.com/pairing?p=%s&d=%s&pwd=%s&sct=%s",
            productId,
            deviceId,
            pairingPassword,
            pairingServerConnectToken);

    return buffer;
}

char* generate_pairing_string(const char* productId, const char* deviceId, const char* pairingPassword, const char* pairingServerConnectToken)
{
    char* buffer = calloc(1, 1024);
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


    /**
     * Load data files
     */
    struct device_config dc;
    device_config_init(&dc);

    if (!load_device_config(tunnel->deviceConfigFile, &dc, &logger)) {
        printf("Failed to start device because a valid `%s` configuration file is missing. see --help for information about this file." NEWLINE, tunnel->deviceConfigFile);
        return false;
    }

    struct iam_config iamConfig;
    iam_config_init(&iamConfig);

    if (!load_iam_config(&iamConfig, tunnel->iamConfigFile, &logger)) {
        print_iam_config_load_failed(tunnel->iamConfigFile);
        return false;
    }

    struct tcp_tunnel_state tcpTunnelState;
    tcp_tunnel_state_init(&tcpTunnelState);

    if (!load_tcp_tunnel_state(&tcpTunnelState, tunnel->stateFile, &logger)) {
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
    nabto_device_enable_mdns(device);


    struct nm_iam iam;
    nm_iam_init(&iam, device, &logger);

    if (tcpTunnelState.pairingPassword != NULL) {
        nm_iam_enable_password_pairing(&iam, tcpTunnelState.pairingPassword);
        tunnel->pairingPassword = strdup(tcpTunnelState.pairingPassword);
    }

    if (tcpTunnelState.pairingServerConnectToken != NULL) {
        nm_iam_enable_remote_pairing(&iam, tcpTunnelState.pairingServerConnectToken);
        tunnel->pairingServerConnectToken = strdup(tcpTunnelState.pairingServerConnectToken);
    }

    struct tcp_tunnel_service* service;
    NN_VECTOR_FOREACH(&service, &tunnel->services)
    {
        nabto_device_add_tcp_tunnel_service(device, service->id, service->type, service->host, service->port);
    }

    char* deviceFingerprint;
    nabto_device_get_device_fingerprint_full_hex(device, &deviceFingerprint);

    char* pairingUrl = generate_pairing_url(dc.productId, dc.deviceId, tcpTunnelState.pairingPassword, tcpTunnelState.pairingServerConnectToken);
    char* pairingString = generate_pairing_string(dc.productId, dc.deviceId, tcpTunnelState.pairingPassword, tcpTunnelState.pairingServerConnectToken);

    // add users to iam module.
    struct nm_iam_user* user;
    NN_VECTOR_FOREACH(&user, &tcpTunnelState.users)
    {
        nm_iam_add_user(&iam, user);
    }
    nn_vector_clear(&tcpTunnelState.users);

    // add roles to iam module
    struct nm_iam_role* role;
    NN_VECTOR_FOREACH(&role, &iamConfig.roles) {
        nm_iam_add_role(&iam, role);
    }
    nn_vector_clear(&iamConfig.roles);

    // add policies to iam module
    struct nm_policy* policy;
    NN_VECTOR_FOREACH(&policy, &iamConfig.policies) {
        nm_iam_add_policy(&iam, policy);
    }
    nn_vector_clear(&iamConfig.policies);
    iam_config_deinit(&iamConfig);

    uint16_t localPort = 5592;

    printf("######## Nabto TCP Tunnel Device ########" NEWLINE);
    printf("# Product ID:        %s" NEWLINE, dc.productId);
    printf("# Device ID:         %s" NEWLINE, dc.deviceId);
    printf("# Pairing password:  %s" NEWLINE, tcpTunnelState.pairingPassword);
    printf("# Paring SCT:        %s" NEWLINE, tcpTunnelState.pairingServerConnectToken);
    printf("# Pairing URL:       %s" NEWLINE, pairingUrl);
    printf("# Pairing string:    %s" NEWLINE, pairingString);
    printf("# " NEWLINE);
    printf("# Fingerprint:       %s" NEWLINE, deviceFingerprint);
    printf("# Version:           %s" NEWLINE, nabto_device_version());
    printf("# Local UDP Port     %d" NEWLINE, localPort);
    printf("######## Configured TCP Services ########" NEWLINE);
    printf("# "); print_item("Id"); print_item("Type"); print_item("Host"); printf("Port" NEWLINE);
    struct tcp_tunnel_service* item;

    NN_VECTOR_FOREACH(&item, &tunnel->services)
    {
        printf("# "); print_item(item->id); print_item(item->type); print_item(item->host); printf("%d" NEWLINE, item->port);
    }
    printf("########" NEWLINE);

    free(pairingUrl);
    nabto_device_string_free(deviceFingerprint);

    tcp_tunnel_state_deinit(&tcpTunnelState);

    if (args->showState) {
        print_iam_state(&iam);
    } else {
        struct device_event_handler eventHandler;

        device_event_handler_init(&eventHandler, device);

        nm_iam_set_user_changed_callback(&iam, iam_user_changed, tunnel);

        nabto_device_start(device);
        nm_iam_start(&iam);

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


void print_iam_state(struct nm_iam* iam)
{
    struct nn_string_set ss;
    nn_string_set_init(&ss);
    nm_iam_get_users(iam, &ss);

    const char* id;
    NN_STRING_SET_FOREACH(id, &ss)
    {
        struct nm_iam_user* user = nm_iam_find_user(iam, id);
        printf("User: %s, fingerprint: %s" NEWLINE, user->id, user->fingerprint);
    }
    nn_string_set_deinit(&ss);
}


void iam_user_changed(struct nm_iam* iam, const char* id, void* userData)
{
    struct tcp_tunnel* tcpTunnel = userData;

    struct tcp_tunnel_state toWrite;

    tcp_tunnel_state_init(&toWrite);
    if (tcpTunnel->pairingPassword) {
        toWrite.pairingPassword = strdup(tcpTunnel->pairingPassword);
    }
    if (tcpTunnel->pairingServerConnectToken) {
        toWrite.pairingServerConnectToken = strdup(tcpTunnel->pairingServerConnectToken);
    }

    struct nn_string_set userIds;
    nn_string_set_init(&userIds);
    nm_iam_get_users(iam, &userIds);

    const char* uid;
    NN_STRING_SET_FOREACH(uid, &userIds)
    {
        struct nm_iam_user* user = nm_iam_find_user(iam, uid);
        nn_vector_push_back(&toWrite.users, &user);
    }
    nn_string_set_deinit(&userIds);
    save_tcp_tunnel_state(tcpTunnel->stateFile, &toWrite);
    tcp_tunnel_state_deinit(&toWrite);
}

bool make_directory(const char* directory)
{
    mkdir(directory, 0777);
    return true;
}
