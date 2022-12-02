//Warning this file is autogenrated by create_help.py
#include "help.h"
#include <stdio.h>
#define NEWLINE "\n"
void print_help() {
    printf("%s" NEWLINE, "TCP Tunnel Device Help.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "# Arguments.");
    printf("%s" NEWLINE, "  -h, --help          Print help");
    printf("%s" NEWLINE, "  -v, --version       Print version");
    printf("%s" NEWLINE, "  -H, --home-dir      Set alternative home dir, The default home dir is");
    printf("%s" NEWLINE, "                      $HOME/.nabto/edge on linux and mac, and %APPDATA%\\nabto\\edge");
    printf("%s" NEWLINE, "                      on windows");
    printf("%s" NEWLINE, "      --log-level     Set the log level for the application the possible levels");
    printf("%s" NEWLINE, "                      is error, warn, info and trace.");
    printf("%s" NEWLINE, "      --random-ports  Bind the local and the p2p sockets to random UDP ports");
    printf("%s" NEWLINE, "                      instead of the default UDP ports 5592 and 5593.");
    printf("%s" NEWLINE, "      --local-port    Bind the local socket to a specific UDP port instead of");
    printf("%s" NEWLINE, "                      the default UDP port 5592.");
    printf("%s" NEWLINE, "      --p2p-port      Bind the p2p socket to a specific UDP port instead of the");
    printf("%s" NEWLINE, "                      default UDP port 5593");
    printf("%s" NEWLINE, "      --init          Interactively create configuration files the the tcp tunnel.");
    printf("%s" NEWLINE, "      --demo-init     Interactively initialize the TCP tunnel for demo purposes.");
    printf("%s" NEWLINE, "                      This option should be used if a quick proof of concept needs");
    printf("%s" NEWLINE, "                      to be made for demo purposes. This should not be used in a");
    printf("%s" NEWLINE, "                      production setup.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "                      Below are several options which can be used to limit the memory");
    printf("%s" NEWLINE, "                      usage of a device.");
    printf("%s" NEWLINE, "      --limit-connections");
    printf("%s" NEWLINE, "                      Limit the max number of concurrent nabto connections which a");
    printf("%s" NEWLINE, "                      device accepts.");
    printf("%s" NEWLINE, "      --limit-streams Limit the max number of concurrent nabto streams the Device");
    printf("%s" NEWLINE, "                      can handle. Each tunnel connection e.g. tcp connection accounts");
    printf("%s" NEWLINE, "                      for one stream.");
    printf("%s" NEWLINE, "      --limit-stream-segments");
    printf("%s" NEWLINE, "                      Limit the total number of segments used concurrently by the");
    printf("%s" NEWLINE, "                      streaming layer. Each segment consumes roughly 256bytes ram.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "# Files");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "The application uses several files. They are located in subfolders of");
    printf("%s" NEWLINE, "the homedir: config, state and keys.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "The files are by default located in this folder on unix:");
    printf("%s" NEWLINE, "`$HOME/.nabto/edge` and this on Windows `%APPDATA%\\nabto\\edge`. The location can");
    printf("%s" NEWLINE, "be overriden by the home-dir option. In this case basefolder is");
    printf("%s" NEWLINE, "`${home-dir}`.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "## `config/device.json`");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "A configuration file containing the configuration for the device. This");
    printf("%s" NEWLINE, "includes the product id, device id and the host names of servers.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "The format of the json file is");
    printf("%s" NEWLINE, "```");
    printf("%s" NEWLINE, "{");
    printf("%s" NEWLINE, "  \"ProductId\": \"pr-abcd1234\",");
    printf("%s" NEWLINE, "  \"DeviceId\": \"de-abcd1234\",");
    printf("%s" NEWLINE, "  \"Server\": \"optional server hostname\",");
    printf("%s" NEWLINE, "  \"ServerPort\": \"optional port number for the server\"");
    printf("%s" NEWLINE, "}");
    printf("%s" NEWLINE, "```");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "The `ProductId` in the configuration is the product which is");
    printf("%s" NEWLINE, "configured for the group of devices. The product id is found in the cloud");
    printf("%s" NEWLINE, "console.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "The `DeviceId` is the device id for this specific device. This device");
    printf("%s" NEWLINE, "id found in the cloud console.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "The `Server` is an optional hostname of the server the device uses. If");
    printf("%s" NEWLINE, "not set, the default server is used.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "## `config/tcp_tunnel_device_iam_config.json`");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "The `tcp_tunnel_iam.json` is an IAM policies file which contains the");
    printf("%s" NEWLINE, "policies and roles used by the system.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "Read more about the IAM module on http://docs.nabto.com/developer/guides/iam/intro.html.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "## `state/tcp_tunnel_device_iam_state.json`");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "A file containing the state of the application, this file is written");
    printf("%s" NEWLINE, "by the application. A custom state file can be added to devices in");
    printf("%s" NEWLINE, "production such that the devices comes e.g. with some default state.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "## `keys/device.key`");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "The device key file is created if it does not exist.");
    printf("%s" NEWLINE, "");
    printf("%s" NEWLINE, "END OF GENERIC HELP");
}
