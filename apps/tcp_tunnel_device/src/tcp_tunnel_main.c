#include "iam_config.h"
#include "tcp_tunnel_state.h"
#include "tcp_tunnel_services.h"
#include "device_event_handler.h"

#include <nabto/nabto_device.h>
#include <apps/common/device_config.h>
#include <apps/common/private_key.h>

#include <modules/iam/nm_iam.h>
#include <modules/iam/nm_iam_user.h>

#include <platform/np_string_set.h>


#include <gopt/gopt.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>

#define NEWLINE "\n"

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

    char* deviceConfigFile;
    char* keyFile;
    char* stateFile;
    char* iamConfigFile;
    char* servicesFile;
    char* privateKeyFile;
};

static void signal_handler(int s);

static char* generate_private_key_file_name(const char* productId, const char* deviceId);
static void print_iam_state(struct nm_iam* iam);

void print_version()
{
    printf("TCP Tunnel Device Version: %s" NEWLINE, nabto_device_version());
}

void print_help()
{
    printf("TCP Tunnel Device" NEWLINE);
    printf(NEWLINE);
    printf("Usage:" NEWLINE);
    printf(" -h, --help,    Print help text" NEWLINE);
    printf(" -v, --version, Print version info" NEWLINE);
    printf(" -H, --homedir, Specify the homedir for the configuration files" NEWLINE);
    printf("   , --show-state, Show the state of the TCP Tunnelling Device" NEWLINE);
    printf("   , --log-level, Set the log level to use, valid options is error,warn,info,trace" NEWLINE);
    printf(NEWLINE);
    printf("The following configuration files exists:" NEWLINE);
    printf(" - HOME_DIR/device_config.json this file contains product id, device id and optionally settings the client needs to connect to the device" NEWLINE);
    printf(" - HOME_DIR/<ProductId>_<DeviceId>.key this file contains the private key the device uses." NEWLINE);
    printf(" - HOME_DIR/tcp_tunnel_state.json This file contains the runtime state of the tcp tunnelling device." NEWLINE);
    printf(" - HOME_DIR/tcp_tunnel_policies.json This file contains the policies the tcp tunnelling device uses in its IAM module." NEWLINE);
    printf(" - HOME_DIR/tcp_tunnel_services.json This file contains the services this tunnel exposes." NEWLINE);
}

void print_device_config_load_failed(const char* fileName, const char* errorText)
{
    printf("Could not open or parse the device config file (%s) reason: %s" NEWLINE, fileName, errorText);
    printf("Please ensure the file exists and has the following format." NEWLINE);
    printf("{" NEWLINE);
    printf("  \"ProductId\": \"<product_id>\"," NEWLINE);
    printf("  \"DeviceId\": \"<device_id>\"," NEWLINE);
    printf("  \"Server\": \"<hostname>\"," NEWLINE);
    printf("  \"client\": {" NEWLINE);
    printf("    \"ServerKey\": \"<server_key>\"," NEWLINE);
    printf("    \"ServerUrl\": \"<server_url>\"," NEWLINE);
    printf("  }" NEWLINE);
    printf("}" NEWLINE);
}

void print_iam_config_load_failed(const char* fileName, const char* errorText)
{
    printf("Could not open or parse IAM config file (%s) reason: %s" NEWLINE, fileName, errorText);
}

void print_tcp_tunnel_state_load_failed(const char* fileName, const char* errorText)
{
    printf("Could not load TCP tunnel state file (%s) reason: %s" NEWLINE, fileName, errorText);
}

void print_start_text(struct args* args)
{
    printf("TCP Tunnel Device" NEWLINE);
}

void print_private_key_file_load_failed(const char* fileName, const char* errorText)
{
    printf("Could not load the private key (%s) reason: %s" NEWLINE, fileName, errorText);
}

static bool parse_args(int argc, char** argv, struct args* args)
{
    const char x1s[] = "h";      const char* x1l[] = { "help", 0 };
    const char x2s[] = "v";      const char* x2l[] = { "version", 0 };
    const char x3s[] = "";       const char* x3l[] = { "log-level", 0 };
    const char x4s[] = "";       const char* x4l[] = { "show-state", 0 };
    const char x5s[] = "H";      const char* x5l[] = { "homedir", 0 };

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
    gopt_arg(options, OPTION_LOG_LEVEL, &args->logLevel);
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
    free(args->deviceConfigFile);
    free(args->stateFile);
    free(args->iamConfigFile);
    free(args->privateKeyFile);
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

char* generate_pairing_url(const char* productId, const char* deviceId, const char* deviceFingerprint, const char* clientServerUrl, const char* clientServerKey, const char* pairingPassword, const char* pairingServerConnectToken)
{
    char* buffer = calloc(1, 1024); // long enough!

    sprintf(buffer, "https://tcp-tunnel.nabto.com/pairing?ProductId=%s&DeviceId=%s&DeviceFingerprint=%s&ClientServerUrl=%s&ClientServerKey=%s&PairingPassword=%s&ClientServerConnectToken=%s",
            productId,
            deviceId,
            deviceFingerprint,
            clientServerUrl,
            clientServerKey,
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

int main(int argc, char** argv)
{
    struct args args;
    args_init(&args);
    parse_args(argc, argv, &args);

    if (args.showHelp) {
        print_help();
        return 0;
    } else if (args.showVersion) {
        print_version();
        return 0;
    }

    const char* homeEnv = getenv("HOME");
    if (args.homeDir != NULL) {
        // perfect just using the homeDir
    } else if (homeEnv != NULL) {
        args.homeDir = expand_file_name(homeEnv, ".nabto");
    } else {
        printf("Missing HomeDir option or HOME environment variable one of these needs to be set.");
        exit(1);
    }

    args.deviceConfigFile = expand_file_name(args.homeDir, "device_config.json");
    args.stateFile = expand_file_name(args.homeDir, "tcp_tunnel_state.json");
    args.iamConfigFile = expand_file_name(args.homeDir, "tcp_tunnel_iam_config.json");
    args.servicesFile = expand_file_name(args.homeDir, "tcp_tunnel_services.json");


    struct device_config dc;
    device_config_init(&dc);

    const char* errorText;
    if (!load_device_config(args.deviceConfigFile, &dc, &errorText)) {
        print_device_config_load_failed(args.deviceConfigFile, errorText);
        exit(1);
    }

    char* privateKeyFileName = generate_private_key_file_name(dc.productId, dc.deviceId);
    args.privateKeyFile = expand_file_name(args.homeDir, privateKeyFileName);
    free(privateKeyFileName);

    struct iam_config iamConfig;
    iam_config_init(&iamConfig);

    if (!load_iam_config(&iamConfig, args.iamConfigFile, &errorText)) {
        print_iam_config_load_failed(args.iamConfigFile, errorText);
    }

    struct tcp_tunnel_state tcpTunnelState;
    tcp_tunnel_state_init(&tcpTunnelState);

    if (!load_tcp_tunnel_state(&tcpTunnelState, args.stateFile, &errorText)) {
        print_tcp_tunnel_state_load_failed(args.stateFile, errorText);
    }

    NabtoDevice* device = nabto_device_new();

    if (args.logLevel != NULL) {
        nabto_device_set_log_std_out_callback(device);
        nabto_device_set_log_level(device, args.logLevel);
    }



    nabto_device_set_product_id(device, dc.productId);
    nabto_device_set_device_id(device, dc.deviceId);
    nabto_device_set_server_url(device, dc.server);
    nabto_device_enable_mdns(device);

    struct nm_iam iam;
    nm_iam_init(&iam, device);



    char* privateKey;
    if (!load_or_create_private_key(device, args.privateKeyFile, &privateKey, &errorText)) {
        print_private_key_file_load_failed(args.privateKeyFile, errorText);
    }

    nabto_device_set_private_key(device, privateKey);

    if (tcpTunnelState.pairingPassword != NULL) {
        nm_iam_enable_password_pairing(&iam, tcpTunnelState.pairingPassword);
    }

    if (tcpTunnelState.pairingServerConnectToken != NULL) {
        nm_iam_enable_remote_pairing(&iam, tcpTunnelState.pairingServerConnectToken);
    }

    struct np_vector services;
    np_vector_init(&services, NULL);

    if (!load_tcp_tunnel_services(&services, args.servicesFile, &errorText))
    {
        printf("Failed to load TCP Services from (%s) reason: %s", args.servicesFile, errorText);
    }

    struct tcp_tunnel_service* service;
    NP_VECTOR_FOREACH(service, &services)
    {
        nabto_device_add_tcp_tunnel_service(device, service->id, service->type, service->host, service->port);
        tcp_tunnel_service_free(service);
    }
    np_vector_clear(&services);

    char* deviceFingerprint;
    nabto_device_get_device_fingerprint_full_hex(device, &deviceFingerprint);

    char* pairingUrl = generate_pairing_url(dc.productId, dc.deviceId, deviceFingerprint, dc.clientServerUrl, dc.clientServerKey, tcpTunnelState.pairingPassword, tcpTunnelState.pairingServerConnectToken);

    // add users to iam module.
    struct nm_iam_user* user;
    NP_VECTOR_FOREACH(user, &tcpTunnelState.users)
    {
        nm_iam_add_user(&iam, user);
    }
    np_vector_clear(&tcpTunnelState.users);

    // add roles to iam module
    struct nm_iam_role* role;
    NP_VECTOR_FOREACH(role, &iamConfig.roles) {
        nm_iam_add_role(&iam, role);
    }
    np_vector_clear(&iamConfig.roles);

    // add policies to iam module
    struct nm_policy* policy;
    NP_VECTOR_FOREACH(policy, &iamConfig.policies) {
        nm_iam_add_policy(&iam, policy);
    }
    np_vector_clear(&iamConfig.policies);


    printf("######## Nabto TCP Tunnel Device ########" NEWLINE);
    printf("# Product ID:        %s" NEWLINE, dc.productId);
    printf("# Device ID:         %s" NEWLINE, dc.deviceId);
    printf("# Fingerprint:       %s" NEWLINE, deviceFingerprint);
    printf("# Pairing password:  %s" NEWLINE, tcpTunnelState.pairingPassword);
    printf("# Paring SCT:        %s" NEWLINE, tcpTunnelState.pairingServerConnectToken);
    printf("# Client Server Url: %s" NEWLINE, dc.clientServerUrl);
    printf("# Client Server Key: %s" NEWLINE, dc.clientServerKey);
    printf("# Version:           %s" NEWLINE, nabto_device_version());
    printf("# Pairing URL:       %s" NEWLINE, pairingUrl);
    printf("######## Configured TCP Services ########" NEWLINE);
    printf("# "); print_item("Id"); print_item("Type"); print_item("Host"); printf("Port" NEWLINE);
    struct tcp_tunnel_service* item;

    NP_VECTOR_FOREACH(item, &services)
    {
        printf("# "); print_item(item->id); print_item(item->type); print_item(item->host); printf("%d" NEWLINE, item->port);
    }
    printf("########" NEWLINE);


    if (args.showState) {
        print_iam_state(&iam);
    } else {
        struct device_event_handler eventHandler;

        device_event_handler_init(&eventHandler, device);

        nabto_device_start(device);
        nm_iam_start(&iam);

        // Wait for the user to press Ctrl-C

        struct sigaction sigIntHandler;

        sigIntHandler.sa_handler = signal_handler;
        sigemptyset(&sigIntHandler.sa_mask);
        sigIntHandler.sa_flags = 0;

        sigaction(SIGINT, &sigIntHandler, NULL);

        pause();
        NabtoDeviceFuture* fut = nabto_device_future_new(device);
        nabto_device_close(device, fut);
        nabto_device_future_wait(fut);
        nabto_device_future_free(fut);
        nabto_device_stop(device);

        device_event_handler_deinit(&eventHandler);
    }



    nabto_device_stop(device);
    nm_iam_deinit(&iam);
    nabto_device_free(device);

    args_deinit(&args);

}


static char* generate_private_key_file_name(const char* productId, const char* deviceId)
{
    // productId_deviceId.key
    size_t outLength = strlen(productId) + 1 + strlen(deviceId) + 4;
    char* str = malloc(outLength+1);
    if (str == NULL) {
        return NULL;
    }
    sprintf(str, "%s_%s.key", productId, deviceId);
    str[outLength] = 0;
    return str;
}


void signal_handler(int s)
{
}


void print_iam_state(struct nm_iam* iam)
{
    struct np_string_set ss;
    np_string_set_init(&ss);
    nm_iam_get_users(iam, &ss);

    const char* id;
    NP_STRING_SET_FOREACH(id, &ss)
    {
        struct nm_iam_user* user = nm_iam_find_user(iam, id);
        printf("User: %s, fingerprint: %s" NEWLINE, user->id, user->fingerprint);
    }
}
