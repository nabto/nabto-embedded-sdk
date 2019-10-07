#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>

#include "json_config.hpp"

#include <iostream>
#include <cxxopts.hpp>

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

static bool init_stream_echo(const std::string& configFile, const std::string& productId, const std::string& deviceId, const std::string& server);
static void run_stream_echo(const std::string& configFile, const std::string& logLevel);


static NabtoDeviceError allow_anyone_to_connect(NabtoDeviceConnectionRef connectionReference, const char* action, void* attributes, size_t attributesLength, void* userData);

// stream echo handlers
static void startListenForEchoStream(NabtoDevice* device);
static void newEchoStream(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void streamAccepted(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void startRead(struct StreamEchoState* state);
static void hasRead(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void startWrite(struct StreamEchoState* state);
static void wrote(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void startClose(struct StreamEchoState* state);
static void closed(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void abortStream(struct StreamEchoState* state);

#define READ_BUFFER_SIZE 1024

struct StreamEchoState {
    NabtoDeviceStream* handle;
    uint8_t readBuffer[1024];
    size_t readLength;
};


int main(int argc, char** argv)
{
    cxxopts::Options options("Stream Echo", "Nabto stream echo example.");


    options.add_options("General")
        ("h,help", "Show help")
        ("i,init", "Write configuration to the config file and create a a private key")
        ("c,config", "Config file to write to")
        ("log-level", "Set the log level");

    options.add_options("Init Parameters")
        ("p,product", "Product id", cxxopts::value<std::string>())
        ("d,device", "Device id", cxxopts::value<std::string>())
        ("s,server", "hostname of the server", cxxopts::value<std::string>());
    try {
        auto result = options.parse(argc, argv);

        if (result.count("help"))
        {
            std::cout << options.help() << std::endl;
            exit(0);
        }

        if (result.count("init") > 0) {
            std::string configFile = result["config"].as<std::string>();
            std::string productId = result["product"].as<std::string>();
            std::string deviceId = result["device"].as<std::string>();
            std::string server = result["server"].as<std::string>();
            if (!init_stream_echo(configFile, productId, deviceId, server)) {
                std::cerr << "Initialization failed" << std::endl;
            }
        } else {
            std::string configFile = result["config"].as<std::string>();
            std::string logLevel = result["log-level"].as<std::string>();
            run_stream_echo(configFile, logLevel);
        }
    } catch (const cxxopts::OptionException& e) {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        std::cout << options.help() << std::endl;
        exit(-1);
    } catch (const std::domain_error& e) {
        std::cout << "Error parsing options: " << e.what() << std::endl;
        std::cout << options.help() << std::endl;
        exit(-1);
    }
    return 0;
}

bool init_tcptunnel(const std::string& configFile, const std::string& productId, const std::string& deviceId, const std::string& server)
{
    if (json_config_exists(configFile)) {
        std::cerr << "The config already file exists, remove " << configFile << " and try again" << std::endl;
        exit(2);
    }

    json config;

    NabtoDevice* device = nabto_device_new();
    NabtoDeviceError ec;

    char* str;
    char* fp;
    ec = nabto_device_experimental_util_create_private_key(device, &str);
    std::string privateKey(str);
    if (ec) {
        std::cerr << "Error creating private key" << std::endl;
        return false;
    }
    ec = nabto_device_set_private_key(device, str);
    if (ec) {
        std::cerr << "Error setting private key" << std::endl;
        return false;
    }
    ec = nabto_device_get_device_fingerprint_hex(device, &fp);
    if (ec) {
        std::cerr << "Error getting Fingerprint" << std::endl;
        return false;
    }

    std::cout << "Created new private key with fingerprint: " << fp << std::endl;
    nabto_device_string_free(fp);
    nabto_device_string_free(str);

    config["PrivateKey"] = privateKey;
    config["ProductId"] = productId;
    config["DeviceId"] = deviceId;
    config["Server"] = server;

    json_config_save(configFile, config);

    nabto_device_free(device);

    return true;
}

NabtoDeviceStream* streamHandle;

void run_tcptunnel(const std::string& configFile, const std::string& logLevel)
{
    NabtoDeviceError ec;
    json config;
    if (!json_config_load(configFile, config)) {
        std::cerr << "The config file " << configFile << " does not exists, run with --init to create the config file" << std::endl;
        exit(-1);
    }

    NabtoDevice* device = nabto_device_new();

    auto productId = config["ProductId"].get<std::string>();
    auto deviceId  = config["DeviceId"].get<std::string>();
    auto server = config["Server"].get<std::string>();
    auto privateKey = config["PrivateKey"].get<std::string>();

    ec = nabto_device_set_product_id(device, productId.c_str());
    if (ec) {
        std::cerr << "Could not set product id" << std::endl;
    }
    ec = nabto_device_set_device_id(device, deviceId.c_str());
    if (ec) {
        std::cerr << "Could not set device id" << std::endl;
    }
    ec = nabto_device_set_server_url(device, server.c_str());
    if (ec) {
        std::cerr << "Could not set server url" << std::endl;
    }
    ec = nabto_device_set_private_key(device, privateKey.c_str());
    if (ec) {
        std::cerr << "Could not set private key" << std::endl;
    }

    ec = nabto_device_enable_mdns(device);
    if (ec) {
        std::cerr << "Failed to enable mdns" << std::endl;
    }

    ec = nabto_device_log_set_level(device, logLevel.c_str());
    if (ec) {
        std::cerr << "Failed to set loglevel" << std::endl;
    }
    ec = nabto_device_log_set_std_out_callback(device);
    if (ec) {
        std::cerr << "Failed to enable stdour logging" << std::endl;
    }

    ec = nabto_device_iam_override_check_access_implementation(device, allow_anyone_to_connect, NULL);
    if (ec) {
        std::cerr << "Could not override iam check access implementation" << std::endl;
    }

    // run application
    ec = nabto_device_start(device);
    if (ec != NABTO_DEVICE_EC_OK) {
        std::cerr << "Failed to start device" << std::endl;
        return;
    }

    char* fpTemp;
    ec = nabto_device_get_device_fingerprint_hex(device, &fpTemp);
    if (ec) {
        std::cerr << "Could not get fingerprint of the device" << std::endl;
    }
    std::string fp(fpTemp);
    nabto_device_string_free(fpTemp);

    std::cout << "Device " << productId << "." << deviceId << " Started with fingerprint " << std::string(fp) << std::endl;

    NabtoDeviceFuture* fut = nabto_device_stream_listen(device, 42, &streamHandle);
    nabto_device_future_set_callback(fut, newEchoStream, device);
    initStreamEchoListen(device);

    // Wait for the user to press Ctrl-C

    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = my_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

    pause();

    nabto_device_free(device);
    exit(0);
}

NabtoDeviceError allow_anyone_to_connect(NabtoDeviceConnectionRef connectionReference, const char* action, void* attributes, size_t attributesLength, void* userData)
{
    return NABTO_DEVICE_EC_OK;
}

// handle echo streams
void startListenForEchoStream(NabtoDevice* device) {
    NabtoDeviceFuture* fut = nabto_device_stream_listen(device, 42, &streamHandle);
    nabto_device_future_set_callback(fut, newEchoStream, device);
}

void newEchoStream(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    NabtoDeviceFutureFree(future);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }
    NabtoDevice* device = userData;
    NabtoDeviceFuture* acceptFuture = nabto_device_stream_accept(streamHandle);

    nabto_device_future_set_callback(acceptFuture, streamAccepted, device);

    // listen for next stream
    startListenForEchoStream(device)
}

void streamAccepted(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    nabto_device_future_free(future);
    NabtoDeviceStream* handle = userData;
    if (ec) {
        nabto_device_stream_free(handle);
        return;
    }

    struct StreamEchoState* state = calloc(1, sizeof(struct StreamEchoState));
    state->handle = handle;
    startRead(state);
}

void startRead(struct StreamEchoState* state)
{
    NabtoDeviceFuture* readFuture = nabto_device_stream_read_some(state->handle, state->readBuffer, READ_BUFFER_SIZE, &state->read);
    nabto_device_future_set_callback(readFuture, hasRead, state);
}

void hasRead(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    struct StreamEchoState* state = userData;
    nabto_device_future_free(future);
    if (ec == NABTO_DEVICE_EC_EOF) {
        // make a nice shutdown
        startClose(state);
    }
    if (ec != NABTO_DEVICE_EC_OK) {
        abortStream(state);
        return;
    }
    startWrite(state);
}

void startWrite(struct StreamEchoState* state)
{
    NabtoDeviceFuture* writeFuture = nabto_device_stream_write_all(state->handle, state->readBuffer, state->readLength);
    nabto_device_future_set_callback(writeFuture, wrote, state);
}

void wrote(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    struct StreamEchoState* state = userData;
    if (ec != NABTO_DEVICE_EC_OK) {
        // just free the stream, there's no hope for it.
        abortStream(state);
        return;
    }
    startRead(state);
}

void startClose(struct StreamEchoState* state)
{
    NabtoDeviceFuture* closeFuture = nabto_device_stream_close(state->handle);
    nabto_device_future_set_callback(writeFuture, closed, state);
}

void closed(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    // ignore error code, just release the resources.
    struct StreamEchoState* state = userData;
    nabto_device_stream_free(state->handle);
    free(state);
}

void abortStream(struct StreamEchoState* state)
{
    nabto_device_stream_free(state->handle);
    free(state);
}
