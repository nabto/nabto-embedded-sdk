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

#include <sys/types.h>

#if defined(_WIN32)
#include <direct.h>
#define HOMEDIR_ENV_VARIABLE "APPDATA"
#define HOMEDIR_NABTO_FOLDER "nabto"
#define NEWLINE "\r\n"
#else
#include <sys/stat.h>
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
    OPTION_SPECIFIC_LOCAL_PORT,
    OPTION_SPECIFIC_P2P_PORT,
    OPTION_INIT,
    OPTION_DEMO_INIT,
    OPTION_MAX_CONNECTIONS,
    OPTION_MAX_STREAMS,
    OPTION_MAX_STREAM_SEGMENTS
};

struct args {
    bool showHelp;
    bool showVersion;
    bool showState;
    const char* logLevel;
    char* homeDir;
    bool randomPorts;
    uint16_t localPort;
    uint16_t p2pPort;
    bool init;
    bool demo_init;
    int maxConnections;
    int maxStreams;
    int maxStreamSegments;
};

static struct nn_allocator defaultAllocator = {
  .calloc = calloc,
  .free = free
};

static struct tcp_tunnel* tunnel_ = NULL;

static void signal_handler(int s);

static void print_iam_state(struct nm_iam_state* state);
static void iam_user_changed(struct nm_iam* iam, void* userData);
static bool make_directory(const char* directory);

static struct tcp_tunnel* tcp_tunnel_new();
static void tcp_tunnel_free(struct tcp_tunnel* tunnel);

struct nn_allocator* get_default_allocator()
{
    return &defaultAllocator;
}

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
    (void)args;
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
    const char x1s[]  = "h";      const char* x1l[]  = { "help", 0 };
    const char x2s[]  = "v";      const char* x2l[]  = { "version", 0 };
    const char x3s[]  = "";       const char* x3l[]  = { "log-level", 0 };
    const char x4s[]  = "";       const char* x4l[]  = { "show-state", 0 };
    const char x5s[]  = "H";      const char* x5l[]  = { "home-dir", 0 };
    const char x6s[]  = "";       const char* x6l[]  = { "random-ports", 0 };
    const char x7s[]  = "";       const char* x7l[]  = { "local-port", 0 };
    const char x8s[]  = "";       const char* x8l[]  = { "p2p-port", 0 };
    const char x9s[]  = "";       const char* x9l[]  = { "init", 0 };
    const char x10s[] = "";       const char* x10l[] = { "demo-init", 0 };
    const char x11s[] = "";       const char* x11l[] = { "limit-connections", 0 };
    const char x12s[] = "";       const char* x12l[] = { "limit-streams", 0 };
    const char x13s[] = "";       const char* x13l[] = { "limit-stream-segments", 0 };

    const struct { int k; int f; const char *s; const char*const* l; } opts[] = {
        { OPTION_HELP, GOPT_NOARG, x1s, x1l },
        { OPTION_VERSION, GOPT_NOARG, x2s, x2l },
        { OPTION_LOG_LEVEL, GOPT_ARG, x3s, x3l },
        { OPTION_SHOW_STATE, GOPT_NOARG, x4s, x4l },
        { OPTION_HOME_DIR, GOPT_ARG, x5s, x5l },
        { OPTION_RANDOM_PORTS, GOPT_NOARG, x6s, x6l },
        { OPTION_SPECIFIC_LOCAL_PORT, GOPT_ARG, x7s, x7l },
        { OPTION_SPECIFIC_P2P_PORT, GOPT_ARG, x8s, x8l },
        { OPTION_INIT, GOPT_NOARG, x9s, x9l },
        { OPTION_DEMO_INIT, GOPT_NOARG, x10s, x10l },
        { OPTION_MAX_CONNECTIONS, GOPT_ARG, x11s, x11l },
        { OPTION_MAX_STREAMS, GOPT_ARG, x12s, x12l },
        { OPTION_MAX_STREAM_SEGMENTS, GOPT_ARG, x13s, x13l },
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

    const char* localPort = NULL;
    if (gopt_arg(options, OPTION_SPECIFIC_LOCAL_PORT, &localPort)) {
        args->localPort = atoi(localPort);
    }

    const char* p2pPort = NULL;
    if (gopt_arg(options, OPTION_SPECIFIC_P2P_PORT, &p2pPort)) {
        args->p2pPort = atoi(p2pPort);
    }

    if (gopt(options, OPTION_INIT)) {
        args->init = true;
    }

    if (gopt(options, OPTION_DEMO_INIT)) {
        args->init = true;
        args->demo_init = true;
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

    const char* maxConnectionsStr;
    if (gopt_arg(options, OPTION_MAX_CONNECTIONS, &maxConnectionsStr)) {
        args->maxConnections = atoi(maxConnectionsStr);
    }

    const char* maxStreamsStr;
    if (gopt_arg(options, OPTION_MAX_STREAMS, &maxStreamsStr)) {
        args->maxStreams = atoi(maxStreamsStr);
    }

    const char* maxStreamSegmentsStr;
    if (gopt_arg(options, OPTION_MAX_STREAM_SEGMENTS, &maxStreamSegmentsStr)) {
        args->maxStreamSegments = atoi(maxStreamSegmentsStr);
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

struct tcp_tunnel* tcp_tunnel_new()
{
    struct tcp_tunnel* tunnel = calloc(1, sizeof(struct tcp_tunnel));
    if (tunnel == NULL) {
        return NULL;
    }
    nn_vector_init(&tunnel->services, sizeof(void*), &defaultAllocator);

    tunnel->device = nabto_device_new();
    if (tunnel->device == NULL) {
        tcp_tunnel_free(tunnel);
        return NULL;
    }
    tunnel->startFuture = nabto_device_future_new(tunnel->device);
    tunnel->closeFuture = nabto_device_future_new(tunnel->device);

    tunnel->iamConfig = nm_iam_configuration_new();
    tunnel->tcpTunnelState = nm_iam_state_new();

    if (tunnel->startFuture != NULL &&
        tunnel->closeFuture != NULL &&
        tunnel->iamConfig != NULL &&
        tunnel->tcpTunnelState != NULL)
    {
        return tunnel;
    }
    tcp_tunnel_free(tunnel);
    return NULL;
}

void tcp_tunnel_free(struct tcp_tunnel* tunnel)
{
    if (tunnel == NULL) {
        return;
    }
    free(tunnel->deviceConfigFile);
    free(tunnel->stateFile);
    free(tunnel->iamConfigFile);
    free(tunnel->privateKeyFile);
    free(tunnel->servicesFile);

    struct tcp_tunnel_service* service;
    NN_VECTOR_FOREACH(&service, &tunnel->services)
    {
        tcp_tunnel_service_free(service);
    }
    nn_vector_deinit(&tunnel->services);

    nm_iam_state_free(tunnel->tcpTunnelState);
    nm_iam_configuration_free(tunnel->iamConfig);

    nabto_device_future_free(tunnel->closeFuture);
    nabto_device_future_free(tunnel->startFuture);
    nabto_device_free(tunnel->device);

    free(tunnel);
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



    bool status = false;
    struct tcp_tunnel* tunnel = tcp_tunnel_new();
    if (tunnel != NULL) {
        status = handle_main(&args, tunnel);
    }
    tcp_tunnel_free(tunnel);
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
        if (dotNabto == NULL || args->homeDir == NULL) {
            return false;
        }
        make_directory(dotNabto);
        free(dotNabto);


        make_directory(args->homeDir);
    } else {
        printf("Missing HomeDir option or HOME environment variable one of these needs to be set." NEWLINE);
        return false;
    }

    struct nn_log logger;
    logging_init(tunnel->device, &logger, args->logLevel);

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
        if (!load_or_create_private_key(tunnel->device, tunnel->privateKeyFile, &logger)) {
            print_private_key_file_load_failed(tunnel->privateKeyFile);
            return false;
        }

        bool success = false;
        if (args->demo_init) {
            success = tcp_tunnel_demo_config(tunnel);
        } else {
            success = tcp_tunnel_config_interactive(tunnel);
        }

        if (!success) {
            printf("Init of the configuration and state failed" NEWLINE);
            return false;
        } else {
            char* deviceFingerprint;
            nabto_device_get_device_fingerprint(tunnel->device, &deviceFingerprint);
            printf("The configuration and state has been initialized" NEWLINE);
            printf("The Fingerprint must be configured for this device in the Nabto Cloud Console before it will be allowed to attach to the Basestation. If you want to reuse an already configured fingerprint, you can copy the corresponding private key to %s" NEWLINE, tunnel->privateKeyFile);
            printf("The device Fingerprint is: %s" NEWLINE, deviceFingerprint);
            return true;
        }
    } else {
        // check that all files exists
        if (!string_file_exists(tunnel->deviceConfigFile)) {
            printf("Missing device config %s, initialize it with --init or --demo-init" NEWLINE, tunnel->deviceConfigFile);
            return false;
        }

        if(!string_file_exists(tunnel->iamConfigFile)) {
            printf("Missing IAM configuration file %s, create it with --init or --demo-init" NEWLINE, tunnel->iamConfigFile);
            return false;
        }

        if (!string_file_exists(tunnel->stateFile)) {
            printf("Missing IAM state file %s, create it with --init or --demo-init" NEWLINE, tunnel->stateFile);
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

    if (!iam_config_load(tunnel->iamConfig, tunnel->iamConfigFile, &logger)) {
        print_iam_config_load_failed(tunnel->iamConfigFile);
        return false;
    }


    if (!load_tcp_tunnel_state(tunnel->tcpTunnelState, tunnel->stateFile, &logger)) {
        print_tcp_tunnel_state_load_failed(tunnel->stateFile);
        return false;
    }

    if (!load_tcp_tunnel_services(&tunnel->services, tunnel->servicesFile, &logger))
    {
        printf("Failed to load TCP Services from (%s)" NEWLINE, tunnel->servicesFile);
        return false;
    }

    if (!load_or_create_private_key(tunnel->device, tunnel->privateKeyFile, &logger)) {
        print_private_key_file_load_failed(tunnel->privateKeyFile);
        return false;
    }

    nabto_device_set_product_id(tunnel->device, dc.productId);
    nabto_device_set_device_id(tunnel->device, dc.deviceId);
    nabto_device_set_app_name(tunnel->device, "Tcp Tunnel");
    if (dc.server != NULL) {
        nabto_device_set_server_url(tunnel->device, dc.server);
    }
    if (dc.serverPort != 0) {
        nabto_device_set_server_port(tunnel->device, dc.serverPort);
    }
    nabto_device_enable_mdns(tunnel->device);
    nabto_device_mdns_add_subtype(tunnel->device, "tcptunnel");

    struct nm_iam iam;
    if (!nm_iam_init(&iam, tunnel->device, &logger)) {
        return false;
    }

    if(!nm_iam_load_configuration(&iam, tunnel->iamConfig)) {
        printf("Could not load iam configuration" NEWLINE);
        return false;
    }
    tunnel->iamConfig = NULL; //transfer ownership to iam
    if (!nm_iam_load_state(&iam, tunnel->tcpTunnelState)) {
        printf("Could not load iam state" NEWLINE);
        return false;
    }
    tunnel->tcpTunnelState = NULL; // transfer ownership to iam


    struct tcp_tunnel_service* service;
    NN_VECTOR_FOREACH(&service, &tunnel->services)
    {
        nabto_device_add_tcp_tunnel_service(tunnel->device, service->id, service->type, service->host, service->port);

        struct nn_string_map_iterator it;
        NN_STRING_MAP_FOREACH(it, &service->metadata)
        {
            const char* key = nn_string_map_key(&it);
            const char* val = nn_string_map_value(&it);
            nabto_device_add_tcp_tunnel_service_metadata(tunnel->device, service->id, key, val);
        }
    }

    char* deviceFingerprint;
    nabto_device_get_device_fingerprint(tunnel->device, &deviceFingerprint);

    if (args->randomPorts) {
        nabto_device_set_local_port(tunnel->device, 0);
        nabto_device_set_p2p_port(tunnel->device, 0);
    } else {
        if (args->localPort) {
            nabto_device_set_local_port(tunnel->device, args->localPort);
        }
        if (args->p2pPort) {
            nabto_device_set_p2p_port(tunnel->device, args->p2pPort);
        }
    }

    if (args->maxConnections != 0) {
        nabto_device_limit_connections(tunnel->device, args->maxConnections);
    }
    if (args->maxStreams != 0) {
        nabto_device_limit_streams(tunnel->device, args->maxStreams);
    }
    if (args->maxStreamSegments != 0) {
        nabto_device_limit_stream_segments(tunnel->device, args->maxStreamSegments);
    }

    printf("######## Nabto TCP Tunnel Device ########" NEWLINE);
    printf("# Product ID:        %s" NEWLINE, dc.productId);
    printf("# Device ID:         %s" NEWLINE, dc.deviceId);
    printf("# Fingerprint:       %s" NEWLINE, deviceFingerprint);
    printf("# Version:           %s" NEWLINE, nabto_device_version());
    if (!args->randomPorts) {
        if (args->localPort) {
            printf("# Local UDP Port:    %d" NEWLINE, args->localPort);
        } else {
            printf("# Local UDP Port:    %d" NEWLINE, 5592);
        }
    }

    // Create a copy of the state and print information from it.
    struct nm_iam_state* state = nm_iam_dump_state(&iam);
    if (state == NULL) {
        return false;
    }

    printf("# Friendly Name:     \"%s\"" NEWLINE, state->friendlyName);

    struct nm_iam_user* initialUser = nm_iam_state_find_user_by_username(state, state->initialPairingUsername);

    bool initialUserNeedPairing = initialUser && initialUser->fingerprint == NULL;

    if (state->localInitialPairing && initialUserNeedPairing) {
        printf("# " NEWLINE);
        printf("# The device is not yet paired with the initial user. You can use Local Initial Pairing to get access." NEWLINE);
    }


    if (state->passwordInvitePairing && initialUserNeedPairing)
    {
        printf("# " NEWLINE);
        printf("# The initial user has not been paired yet. You can pair with the device using Password Invite Pairing." NEWLINE);
        printf("# Initial Pairing Usermame:  %s" NEWLINE, initialUser->username);
        if (initialUser->password != NULL) {
            printf("# Initial Pairing Password:  %s" NEWLINE, initialUser->password);
        }
        if (initialUser->sct != NULL) {
            printf("# Initial Pairing SCT:       %s" NEWLINE, initialUser->sct);
        }
        // format the pairing string over the next couple of lines
        printf("# Initial Pairing String:    p=%s,d=%s,u=%s", dc.productId, dc.deviceId, initialUser->username);
        if (initialUser->password != NULL) {
            printf(",pwd=%s",initialUser->password);
        }
        if (initialUser->sct != NULL) {
            printf(",sct=%s", initialUser->sct);
        }
        printf(NEWLINE);

    }

    if (!initialUserNeedPairing) {
        //  we are past the initial user being paired.
        if (state->passwordInvitePairing)
        {
            printf("# " NEWLINE);
            printf("# The device provides Password Invite Pairing, contact the administrator to access." NEWLINE);
        }

        if (state->localOpenPairing) {
            printf("# " NEWLINE);
            printf("# The device offers Local Open Pairing" NEWLINE);
        }
    }

    if (state->passwordOpenPairing && state->passwordOpenPassword != NULL && state->passwordOpenSct != NULL) {
        printf("# " NEWLINE);
        printf("# The device has Password Open Pairing enabled" NEWLINE);
        printf("# Open Pairing Password:  %s" NEWLINE, state->passwordOpenPassword);
        printf("# Open Pairing SCT:       %s" NEWLINE, state->passwordOpenSct);
        printf("# Open Pairing String:    p=%s,d=%s,pwd=%s,sct=%s" NEWLINE, dc.productId, dc.deviceId, state->passwordOpenPassword, state->passwordOpenSct);
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

    nm_iam_state_free(state);

    if (args->showState) {
        struct nm_iam_state* state = nm_iam_dump_state(&iam);
        print_iam_state(state);
        nm_iam_state_free(state);
    } else {
        struct device_event_handler eventHandler;

        device_event_handler_init(&eventHandler, tunnel->device);

        nm_iam_set_state_changed_callback(&iam, iam_user_changed, tunnel);

        nabto_device_start(tunnel->device, tunnel->startFuture);
        NabtoDeviceError ec = nabto_device_future_wait(tunnel->startFuture);
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

        tunnel_ = tunnel;

        fflush(stdout); // flush all printed messages during the startup

        // Wait for the user to press Ctrl-C
        signal(SIGINT, &signal_handler);

        // block until the NABTO_DEVICE_EVENT_CLOSED event is emitted.
        device_event_handler_blocking_listener(&eventHandler);

        nabto_device_stop(tunnel->device);

        device_event_handler_deinit(&eventHandler);
    }

    nabto_device_stop(tunnel->device);
    nm_iam_deinit(&iam);

    device_config_deinit(&dc);

    return true;
}

void signal_handler(int s)
{
    (void)s;
    nabto_device_close(tunnel_->device, tunnel_->closeFuture);
    nabto_device_future_wait(tunnel_->closeFuture);
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
    struct nm_iam_state* state = nm_iam_dump_state(iam);
    if(state == NULL) {
        printf("Error could not dump IAM state" NEWLINE);
    } else if (!save_tcp_tunnel_state(tcpTunnel->stateFile, state)) {
        printf("Could not save tcp_tunnel state to %s" NEWLINE, tcpTunnel->stateFile);
    }
    nm_iam_state_free(state);
}

bool make_directory(const char* directory)
{
#if defined(_WIN32)
    _mkdir(directory);
#else
    mkdir(directory, 0777);
#endif
    return true;
}
