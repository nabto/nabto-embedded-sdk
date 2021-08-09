#include "heat_pump.h"

#include <apps/common/device_config.h>
#include <apps/common/private_key.h>
#include <apps/common/logging.h>

#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include <gopt/gopt.h>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#if defined(_WIN32)
#include <direct.h>
#endif

#if defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>

#ifdef WIN32
const char* homeDirEnvVariable = "APPDATA";
const char* nabtoFolder = "nabto";
#define NEWLINE "\r\n"
#else
const char* homeDirEnvVariable = "HOME";
const char* nabtoFolder = ".nabto";
#define NEWLINE "\n"
#endif

/**
 * The first time the heatpump is started init is called and writes a
 * configuration file. The configuration file is used in subsequent
 * runs of the heatpump.
 */


enum {
    OPTION_HELP = 1,
    OPTION_VERSION,
    OPTION_HOME_DIR,
    OPTION_LOG_LEVEL,
    OPTION_RANDOM_PORTS,
    OPTION_INIT
};



NabtoDevice* device = NULL;

struct args {
    bool showHelp;
    bool showVersion;
    char* homeDir;
    char* logLevel;
    bool randomPorts;
    bool init;
};

static void args_init(struct args* args);
static void args_deinit(struct args* args);
bool parse_args(int argc, char** argv, struct args* args);

static void signal_handler(int s);
static bool make_directory(const char* directory);

static bool make_directories(const char* in);

static bool run_heat_pump(const struct args* args);
static bool run_heat_pump_device(NabtoDevice* device, struct heat_pump* heatPump, const struct args* args);
static void print_missing_device_config_help(const char* filename);
static void print_help();
static void print_version();

const char* heatPumpVersion = "1.0.0";

int main(int argc, char** argv) {
    bool status = true;
    struct args args;
    args_init(&args);

    if (!parse_args(argc, argv, &args)) {
        printf("Cannot parse args" NEWLINE);
        status = false;
    } else {
        if (args.showHelp) {
            print_help();
        } else if (args.showVersion) {
            print_version();
        } else {
            make_directories(args.homeDir);
            status = run_heat_pump(&args);
        }
    }

    args_deinit(&args);
    if (status) {
        exit(0);
    } else {
        exit(1);
    }
}

bool run_heat_pump(const struct args* args)
{
    device = nabto_device_new();
    struct nn_log logger;
    logging_init(device, &logger, args->logLevel);

    struct heat_pump heatPump;
    heat_pump_init(&heatPump, device, &logger);

    bool status = run_heat_pump_device(device, &heatPump, args);

    nabto_device_stop(device);
    heat_pump_deinit(&heatPump);
    nabto_device_free(device);
    return status;
}

bool run_heat_pump_device(NabtoDevice* dev, struct heat_pump* heatPump, const struct args* args)
{
    char buffer[512];
    memset(buffer, 0, 512);

    if (args->homeDir != NULL) {
        snprintf(buffer, 511, "%s/config/device.json", args->homeDir);
        heatPump->deviceConfigFile = strdup(buffer);
        snprintf(buffer, 511, "%s/keys/device.key", args->homeDir);
        heatPump->deviceKeyFile = strdup(buffer);
        snprintf(buffer, 511, "%s/state/heat_pump_device_iam_state.json", args->homeDir);
        heatPump->iamStateFile = strdup(buffer);
        snprintf(buffer, 511, "%s/state/heat_pump_device_state.json", args->homeDir);
        heatPump->heatPumpStateFile = strdup(buffer);
    } else {
        const char* tmp = getenv(homeDirEnvVariable);
        if (tmp == NULL) {
            printf("Cannot get the environment variable %s", homeDirEnvVariable);
        } else {
            snprintf(buffer, 511, "%s/%s/edge/config/device.json", tmp, nabtoFolder);
            heatPump->deviceConfigFile = strdup(buffer);
            snprintf(buffer, 511, "%s/%s/edge/keys/device.key", tmp, nabtoFolder);
            heatPump->deviceKeyFile = strdup(buffer);
            snprintf(buffer, 511, "%s/%s/edge/state/heat_pump_device_iam_state.json", tmp, nabtoFolder);
            heatPump->iamStateFile = strdup(buffer);
            snprintf(buffer, 511, "%s/%s/edge/state/heat_pump_device_state.json", tmp, nabtoFolder);
            heatPump->heatPumpStateFile = strdup(buffer);
        }
    }

    struct device_config deviceConfig;
    device_config_init(&deviceConfig);
    if (!load_device_config(heatPump->deviceConfigFile, &deviceConfig, heatPump->logger)) {
        print_missing_device_config_help(heatPump->deviceConfigFile);
        return false;
    }

    nabto_device_set_product_id(dev, deviceConfig.productId);
    nabto_device_set_device_id(dev, deviceConfig.deviceId);

    if (deviceConfig.server != NULL) {
        nabto_device_set_server_url(dev, deviceConfig.server);
    }

    if (deviceConfig.serverPort != 0) {
        nabto_device_set_server_port(dev, deviceConfig.serverPort);
    }

    device_config_deinit(&deviceConfig);

    if (args->randomPorts) {
        nabto_device_set_local_port(dev, 0);
        nabto_device_set_p2p_port(dev, 0);
    }

    if (!load_or_create_private_key(dev, heatPump->deviceKeyFile, heatPump->logger)) {
        printf("Could not load or create the private key" NEWLINE);
        return false;
    }

    if (args->init) {
        printf("Resetting IAM state" NEWLINE);
        heat_pump_reinit_state(heatPump);
        return true;
    }

    nabto_device_set_app_name(dev, "HeatPump");
    nabto_device_set_app_version(dev, heatPumpVersion);

    nabto_device_enable_mdns(dev);
    nabto_device_mdns_add_subtype(dev, "heatpump");
    nabto_device_mdns_add_txt_item(dev, "fn", "Heat Pump");



    // run application
    heat_pump_start(heatPump);
    NabtoDeviceFuture* fut = nabto_device_future_new(dev);
    nabto_device_start(dev, fut);

    NabtoDeviceError ec;
    ec = nabto_device_future_wait(fut);
    nabto_device_future_free(fut);

    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Failed to start the device" NEWLINE);
        return false;
    }

    char* deviceFingerprint;
    nabto_device_get_device_fingerprint(dev, &deviceFingerprint);


    printf("######## Nabto heat pump device ########" NEWLINE);
    printf("# Product ID:                  %s" NEWLINE, nabto_device_get_product_id(dev));
    printf("# Device ID:                   %s" NEWLINE, nabto_device_get_device_id(dev));
    printf("# Fingerprint:                 %s" NEWLINE, deviceFingerprint);
    printf("# Nabto Version:               %s" NEWLINE, nabto_device_version());
    printf("######## " NEWLINE);

    nabto_device_string_free(deviceFingerprint);
    {
        // Wait for the user to press Ctrl-C

        signal(SIGINT, &signal_handler);
        {
            NabtoDeviceListener* listener = nabto_device_listener_new(dev);
            NabtoDeviceFuture* future = nabto_device_future_new(dev);
            nabto_device_device_events_init_listener(device, listener);
            NabtoDeviceEvent event;
            while(true) {
                nabto_device_listener_device_event(listener, future, &event);
                ec = nabto_device_future_wait(future);
                if (ec != NABTO_DEVICE_EC_OK) {
                    break;
                }
                if (event == NABTO_DEVICE_EVENT_CLOSED) {
                    nabto_device_listener_stop(listener);
                } else if (event == NABTO_DEVICE_EVENT_ATTACHED) {
                    printf("Attached to the basestation" NEWLINE);
                } else if (event == NABTO_DEVICE_EVENT_DETACHED) {
                    printf("Detached from the basestation" NEWLINE);
                } else if (event == NABTO_DEVICE_EVENT_UNKNOWN_FINGERPRINT) {
                    printf("The device fingerprint is not known by the basestation" NEWLINE);
                } else if (event == NABTO_DEVICE_EVENT_WRONG_PRODUCT_ID) {
                    printf("The provided Product ID did not match the fingerprint" NEWLINE);
                } else if (event == NABTO_DEVICE_EVENT_WRONG_DEVICE_ID) {
                    printf("The provided Device ID did not match the fingerprint" NEWLINE);
    }
            }
            nabto_device_future_free(future);
            nabto_device_listener_free(listener);
        }
        fut = nabto_device_future_new(dev);
        nabto_device_close(dev, fut);
        nabto_device_future_wait(fut);
        nabto_device_future_free(fut);
    }
    return true;
}


void args_init(struct args* args)
{
    memset(args, 0, sizeof(struct args));
}

void args_deinit(struct args* args)
{
    free(args->homeDir);
    free(args->logLevel);
}

bool parse_args(int argc, char** argv, struct args* args)
{
    const char x1s[] = "h";      const char* x1l[] = { "help", 0 };
    const char x2s[] = "v";      const char* x2l[] = { "version", 0 };
    const char x3s[] = "H";      const char* x3l[] = { "home-dir", 0 };
    const char x4s[] = "";       const char* x4l[] = { "log-level", 0 };
    const char x5s[] = "";       const char* x5l[] = { "random-ports", 0 };
    const char x6s[] = "";       const char* x6l[] = { "init", 0 };

    const struct { int k; int f; const char *s; const char*const* l; } opts[] = {
        { OPTION_HELP, GOPT_NOARG, x1s, x1l },
        { OPTION_VERSION, GOPT_NOARG, x2s, x2l },
        { OPTION_HOME_DIR, GOPT_ARG, x3s, x3l },
        { OPTION_LOG_LEVEL, GOPT_ARG, x4s, x4l },
        { OPTION_RANDOM_PORTS, GOPT_NOARG, x5s, x5l },
        { OPTION_INIT, GOPT_NOARG, x6s, x6l },
        {0,0,0,0}
    };

    void *options = gopt_sort( & argc, (const char**)argv, opts);

    if (gopt(options, OPTION_HELP)) {
        args->showHelp = true;
    }
    if (gopt(options, OPTION_VERSION)) {
        args->showVersion = true;
    }

    if (gopt(options, OPTION_RANDOM_PORTS)) {
        args->randomPorts = true;
    }

    if (gopt(options, OPTION_INIT)) {
        args->init = true;
    }

    const char* logLevel;
    if (gopt_arg(options, OPTION_LOG_LEVEL, &logLevel)) {
        args->logLevel = strdup(logLevel);
    } else {
        args->logLevel = strdup("error");
    }

    const char* hd = NULL;
    if (gopt_arg(options, OPTION_HOME_DIR, &hd)) {
        args->homeDir = strdup(hd);
    }

    gopt_free(options);
    return true;
}

void signal_handler(int s) {
    // the \r is supposed to fix "^CCaught sig...." it will maybe not work on some platforms.
    printf("\rCaught signal %d, stopping the device" NEWLINE,s);
    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    nabto_device_close(device, fut);
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
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

bool make_directories(const char* in)
{

    char buffer[512];
    memset(buffer, 0, 512);
    if (in == NULL) {
        char* homeEnv = getenv(homeDirEnvVariable);
        if (homeEnv == NULL) {
            return false;
        }
        snprintf(buffer, 511, "%s/%s", homeEnv, nabtoFolder);
        make_directory(buffer);

        snprintf(buffer, 511, "%s/%s/edge", homeEnv, nabtoFolder);
        make_directory(buffer);

        snprintf(buffer, 511, "%s/%s/edge/config", homeEnv, nabtoFolder);
        make_directory(buffer);

        snprintf(buffer, 511, "%s/%s/edge/state", homeEnv, nabtoFolder);
        make_directory(buffer);

        snprintf(buffer, 511, "%s/%s/edge/keys", homeEnv, nabtoFolder);
        make_directory(buffer);
    } else {
        make_directory(in);

        snprintf(buffer, 511, "%s/config", in);
        make_directory(buffer);

        snprintf(buffer, 511, "%s/state", in);
        make_directory(buffer);

        snprintf(buffer, 511, "%s/keys", in);
        make_directory(buffer);
    }
    return true;
}

void print_missing_device_config_help(const char* filename)
{
    printf("The device config is missing (%s). Provide a file with the following format" NEWLINE, filename);
    printf("{" NEWLINE);
    printf("   \"ProductId\": \"pr-12345678\"," NEWLINE);
    printf("   \"DeviceId\": \"de-abcdefgh\"" NEWLINE);
    printf("}" NEWLINE);
}

void print_help() {
    printf(" -h,--help print help" NEWLINE);
    printf(" --version Show version" NEWLINE);
    printf(" -H,--home-dir Home directory for the device. The default Home dir on unix is $HOME/.nabto/edge. On Windows the default home directory is %%APP_DATA%%/nabto/edge. The aplication uses the following files $homedir/keys/device.key, $homedir/config/device.json, $homedir/state/heat_pump_device_iam_state.json, $homedir/state/heat_pump_device_state.json" NEWLINE);
    printf(" --log-level Log level to log (error|info|trace|debug)" NEWLINE);
    printf(" --random-ports Use random ports such that several devices can be running at the same time. The device can still be discovered locally." NEWLINE);
    printf(" --init Reset pump state to factory defaults and remove all paired users." NEWLINE);
}

void print_version() {
    printf("%s" NEWLINE, heatPumpVersion);
}
