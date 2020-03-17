#include "iam_config.h"
#include "tcp_tunnel_state.h"

#include <nabto/nabto_device.h>

#include <apps/common/device_config.h>

#include <gopt/gopt.h>

#include <stdio.h>
#include <stdlib.h>
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
};


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

    struct device_config dc;
    device_config_init(&dc);

    const char* errorText;
    if (!load_device_config(args.deviceConfigFile, &dc, &errorText)) {
        print_device_config_load_failed(args.deviceConfigFile, errorText);
        exit(1);
    }

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


    // setup system

    if (args.showState) {
        //print_state();
        // print state
    } else {
        // run device
    }

    args_deinit(&args);

}
