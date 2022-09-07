#include "thermostat.h"

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
#include <direct.h>´
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
 * The first time the thermostat is started init is called and writes a
 * configuration file. The configuration file is used in subsequent
 * runs of the thermostat.
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

// handling command line arguments
static void args_init(struct args* args);
static void args_deinit(struct args* args);
bool parse_args(int argc, char** argv, struct args* args);

// signal handler to close device cleanly on ^C
static void signal_handler(int s);

// creates directories for persistant state
static bool make_directory(const char* directory);
static bool make_directories(const char* in);

// Starts the thermostat
static bool run_thermostat(const struct args* args);

// Runs the nabto device
static bool run_thermostat_device(NabtoDevice* device, struct thermostat* thermostat, const struct args* args);

// Functions to print info to stdout
static void print_missing_device_config_help(const char* filename);
static void print_help();
static void print_version();

const char* thermostatVersion = "1.0.0";

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
            status = run_thermostat(&args);
        }
    }

    args_deinit(&args);
    if (status) {
        exit(0);
    } else {
        exit(1);
    }
}

bool run_thermostat(const struct args* args)
{
    device = nabto_device_new();
    struct nn_log logger;
    logging_init(device, &logger, args->logLevel);

    char homeBuffer[128];
    memset(homeBuffer, 0, 128);

    char* homeDir = args->homeDir;
    if (homeDir == NULL) {
        const char* tmp = getenv(homeDirEnvVariable);
        if (tmp == NULL) {
            printf("Cannot get the environment variable %s", homeDirEnvVariable);
            return false;
        }
        snprintf(homeBuffer, 127, "%s/%s/edge", tmp, nabtoFolder);
        homeDir = homeBuffer;
    }

    struct thermostat thermostat;
    thermostat_init(&thermostat, device, homeDir, &logger);

    bool status = run_thermostat_device(device, &thermostat, args);

    nabto_device_stop(device);
    thermostat_deinit(&thermostat);
    nabto_device_free(device);
    return status;
}

bool run_thermostat_device(NabtoDevice* dev, struct thermostat* thermostat, const struct args* args)
{
    struct device_config deviceConfig;
    device_config_init(&deviceConfig);
    if (!load_device_config(thermostat->deviceConfigFile, &deviceConfig, thermostat->logger)) {
        print_missing_device_config_help(thermostat->deviceConfigFile);
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

    if (!load_or_create_private_key(dev, thermostat->deviceKeyFile, thermostat->logger)) {
        printf("Could not load or create the private key" NEWLINE);
        return false;
    }

    if (args->init) {
        printf("Resetting IAM state" NEWLINE);
        thermostat_reinit_state(thermostat);
        return true;
    }

    nabto_device_set_app_name(dev, "Thermostat");
    nabto_device_set_app_version(dev, thermostatVersion);

    nabto_device_enable_mdns(dev);
    nabto_device_mdns_add_subtype(dev, "thermostat");
    nabto_device_mdns_add_subtype(dev, "heatpump");
    nabto_device_mdns_add_txt_item(dev, "fn", "Thermostat");



    // run application
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

    const char* pairingString = thermostat_iam_create_pairing_string(
        thermostat, nabto_device_get_product_id(dev),
        nabto_device_get_device_id(dev));
    printf("######## Nabto thermostat device ########" NEWLINE);
    printf("# Product ID:                  %s" NEWLINE, nabto_device_get_product_id(dev));
    printf("# Device ID:                   %s" NEWLINE, nabto_device_get_device_id(dev));
    printf("# Fingerprint:                 %s" NEWLINE, deviceFingerprint);
    if (pairingString != NULL) {
        printf("# Pairing String:              %s" NEWLINE, pairingString);
    } else {
        printf("# Pairing String:              Failed to generate string" NEWLINE);
    }
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

            nabto_device_duration_t tickInterval = 30;

            while(true) {
                nabto_device_listener_device_event(listener, future, &event);
                while(true) {
                    thermostat_update(thermostat, (double)(tickInterval) / 1000.0);

                    if (nabto_device_future_timed_wait(future, tickInterval) != NABTO_DEVICE_EC_FUTURE_NOT_RESOLVED) {
                        break;
                    }
                }

                ec = nabto_device_future_ready(future);
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
        { OPTION_HOME_DIR,GOPT_ARG, x3s, x3l },
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
    char homeBuffer[128];
    memset(homeBuffer, 0, 128);

    const char* homeDir = in;
    if (homeDir == NULL) {
        const char* tmp = getenv(homeDirEnvVariable);
        if (tmp == NULL) {
            printf("Cannot get the environment variable %s", homeDirEnvVariable);
            return false;
        }
        snprintf(homeBuffer, 127, "%s/%s/edge", tmp, nabtoFolder);
        homeDir = homeBuffer;
    }

    make_directory(homeDir);

    snprintf(buffer, 511, "%s/config", homeDir);
    make_directory(buffer);

    snprintf(buffer, 511, "%s/state", homeDir);
    make_directory(buffer);

    snprintf(buffer, 511, "%s/keys", homeDir);
    make_directory(buffer);
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
    printf(" -H,--home-dir Home directory for the device. The default Home dir on unix is $HOME/.nabto/edge. On Windows the default home directory is %%APP_DATA%%/nabto/edge. The aplication uses the following files $homedir/keys/device.key, $homedir/config/device.json, $homedir/state/thermostat_device_iam_state.json, $homedir/state/thermostat_device_state.json" NEWLINE);
    printf(" --log-level Log level to log (error|info|trace|debug)" NEWLINE);
    printf(" --random-ports Use random ports such that several devices can be running at the same time. The device can still be discovered locally." NEWLINE);
    printf(" --init Reset state to factory defaults and remove all paired users." NEWLINE);
}

void print_version() {
    printf("%s" NEWLINE, thermostatVersion);
}
