#include "thermostat.h"

#include <apps/common/device_config.h>
#include <apps/common/string_file.h>
#include <apps/common/private_key.h>
#include <apps/common/logging.h>
#include <apps/common/prompt_stdin.h>

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

#include "thermostat_file.h"
#include "thermostat_state_file_backend.h"

#include <modules/fs/posix/nm_fs_posix.h>

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



static int signalCount = 0;
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
static bool run_thermostat_device(NabtoDevice* device, struct thermostat* thermostat, struct nm_fs* fsImpl, struct thermostat_file* tf, struct thermostat_state_file_backend* tsfb, const struct args* args);

// Functions to print info to stdout
static void print_missing_device_config_help(const char* filename);
static void print_help();
static void print_version();

static void thermostat_reinit_state(struct thermostat* thermostat, struct nm_fs* fsImpl, struct thermostat_file* thermostatFile, struct thermostat_state_file_backend* tsfb);

const char* thermostatVersion = "1.0.0";

int main(int argc, char** argv) {

    // Disable buffering for stdout
    setvbuf(stdout, NULL, _IONBF, 0);
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

    struct nm_fs fsImpl = nm_fs_posix_get_impl();


    struct thermostat thermostat;
    struct thermostat_file thermostatFile;
    struct thermostat_iam thermostatIam;
    struct thermostat_state thermostatState;
    struct thermostat_state_file_backend thermostatStateFileBackend;
    thermostat_file_init(&thermostatFile, homeDir);
    thermostat_state_file_backend_init(&thermostatStateFileBackend, &thermostatState, &fsImpl, thermostatFile.thermostatStateFile);
    thermostat_iam_init(&thermostatIam, device, &fsImpl, thermostatFile.iamStateFile, &logger);
    thermostat_iam_load_state(&thermostatIam);
    thermostat_init(&thermostat, device, &thermostatIam.iam, &thermostatState, &logger);
    if (!thermostate_state_file_backend_load_data(&thermostatStateFileBackend, &logger)) {
        return false;
    }

    bool status = run_thermostat_device(device, &thermostat, &fsImpl, &thermostatFile, &thermostatStateFileBackend, args);

    if (signalCount < 2) {
       nabto_device_stop(device);
    }
    thermostat_deinit(&thermostat);
    thermostat_iam_deinit(&thermostatIam);
    thermostat_state_file_backend_deinit(&thermostatStateFileBackend);
    thermostat_file_deinit(&thermostatFile);
    nabto_device_free(device);
    return status;
}

bool run_thermostat_device(NabtoDevice* dev, struct thermostat* thermostat, struct nm_fs* fsImpl, struct thermostat_file* tf, struct thermostat_state_file_backend* tsfb, const struct args* args)
{
    if (args->init) {
        printf("Initializing Thermostat" NEWLINE);
        thermostat_reinit_state(thermostat, fsImpl, tf, tsfb);
        return true;
    }

    struct device_config deviceConfig;
    device_config_init(&deviceConfig);
    if (!load_device_config(fsImpl, tf->deviceConfigFile, &deviceConfig, thermostat->logger)) {
        print_missing_device_config_help(tf->deviceConfigFile);
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

    if (!load_or_create_private_key(dev, fsImpl, tf->deviceKeyFile, thermostat->logger)) {
        printf("Could not load or create the private key" NEWLINE);
        return false;
    }

    nabto_device_set_app_name(dev, "Thermostat");
    nabto_device_set_app_version(dev, thermostatVersion);

    nabto_device_enable_mdns(dev);
    nabto_device_mdns_add_subtype(dev, "thermostat");
    nabto_device_mdns_add_subtype(dev, "heatpump");

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

    char* pairingString = thermostat_iam_create_pairing_string(
        thermostat->iam, nabto_device_get_product_id(dev),
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

    free(pairingString);
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
                    thermostat_state_file_backend_update(tsfb, (double)(tickInterval) / 1000.0);

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

void close_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* data)
{
    nabto_device_future_free(future);
}

void signal_handler(int s) {
    // the \r is supposed to fix "^CCaught sig...." it will maybe not work on some platforms.
    printf("\rCaught signal %d" NEWLINE,s);
    if (signalCount == 0) {
        signalCount++;
        printf("first signal. Closing the device" NEWLINE);
        NabtoDeviceFuture* fut = nabto_device_future_new(device);
        nabto_device_close(device, fut);
        nabto_device_future_set_callback(fut, close_callback, NULL);
    } else if (signalCount == 1) {
        signalCount++;
        printf("second signal. stopping the device" NEWLINE);
        nabto_device_stop(device);
    } else {
        printf("Signal ignored. Operation in progress" NEWLINE);
    }
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
    printf("The device configuration file is missing (%s). " NEWLINE, filename);
    printf("Run the Thermostat with --init to create a device configuration" NEWLINE);
}

void print_help() {
    printf(" -h,--help      print help" NEWLINE);
    printf("    --version   Show version" NEWLINE);
    printf("    --init      Initialize the Thermostat. Will reset state if run on existing homedir." NEWLINE);
    printf(" -H,--home-dir  Home directory for the device. The default Home dir on unix is $HOME/.nabto/edge." NEWLINE
           "                On Windows the default home directory is %%APP_DATA%%/nabto/edge." NEWLINE
           "                The aplication uses the following files $homedir/keys/device.key, $homedir/config/device.json, " NEWLINE
           "                $homedir/state/thermostat_device_iam_state.json, $homedir/state/thermostat_device_state.json" NEWLINE);
    printf(" --log-level    Log level to log (error|info|trace|debug)" NEWLINE);
    printf(" --random-ports Use random ports such that several devices can be running at the same time. The device can still be discovered locally." NEWLINE);
}

void print_version() {
    printf("%s" NEWLINE, thermostatVersion);
}


void thermostat_reinit_state(struct thermostat* thermostat, struct nm_fs* fsImpl, struct thermostat_file* thermostatFile, struct thermostat_state_file_backend* tsfb)
{
    bool deviceConfigExists = string_file_exists(fsImpl, thermostatFile->deviceConfigFile);
    bool createDeviceConfig = true;

    if (deviceConfigExists) {
        printf("Found device config %s" NEWLINE, thermostatFile->deviceConfigFile);
        createDeviceConfig = prompt_yes_no("A device config already exists, do you want to recreate it?");

    }

    if (createDeviceConfig) {
        printf("Creating configuration: %s." NEWLINE, thermostatFile->deviceConfigFile);
        if (!create_device_config_interactive(fsImpl, thermostatFile->deviceConfigFile)) {
            printf("Failed to create device configuration!" NEWLINE);
            printf(
                "The device will not work until the file is created." NEWLINE);
        }
    }

    thermostat_iam_create_default_state(thermostat->device, fsImpl, thermostatFile->iamStateFile, thermostat->logger);
    thermostat_state_file_backend_create_default_state_file(tsfb);
}
