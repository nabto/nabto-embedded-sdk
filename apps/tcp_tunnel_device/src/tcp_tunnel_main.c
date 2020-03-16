#include <nabto/nabto_device.h>

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
    printf(" - HOME_DIR/device_condfig.json this file contains product id, device id and optionally settings the client needs to connect to the device" NEWLINE);
    printf(" - HOME_DIR/<ProductId>_<DeviceId>.key this file contains the private key the device uses." NEWLINE);
    printf(" - HOME_DIR/tcp_tunnel_state.json This file contains the runtime state of the tcp tunnelling device." NEWLINE);
    printf(" - HOME_DIR/tcp_tunnel_policies.json This file contains the policies the tcp tunnelling device uses in its IAM module." NEWLINE);
}

static bool parse_args(int argc, char** argv)
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
        print_help();
        exit(0);
    } else if (gopt(options, OPTION_VERSION)) {
        print_version();
        exit(0);
    }


    return true;
}

int main(int argc, char** argv)
{
    parse_args(argc, argv);
}
