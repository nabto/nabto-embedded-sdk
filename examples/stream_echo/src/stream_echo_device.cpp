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

#define READ_BUFFER_SIZE 1024

struct StreamEchoState {
    NabtoDeviceStream* stream;
    uint8_t readBuffer[1024];
    size_t readLength;
    struct StreamEchoState* next;
    bool active;
    NabtoDevice* dev;
};

struct StreamEchoState head;

void ctrlCHandler(int s){
    printf("Caught signal %d\n",s);
}


int main(int argc, char** argv)
{
    cxxopts::Options options("Stream Echo", "Nabto stream echo example.");


    options.add_options("General")
        ("h,help", "Show help")
        ("i,init", "Write configuration to the config file and create a a private key")
        ("c,config", "Config file to write to", cxxopts::value<std::string>()->default_value("stream_echo_device.json"))
        ("log-level", "Log level to log (error|info|trace|debug)", cxxopts::value<std::string>()->default_value("info"));

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
    } catch (...) {
        std::cout << options.help() << std::endl;
        exit(-1);
    }
    return 0;
}

bool init_stream_echo(const std::string& configFile, const std::string& productId, const std::string& deviceId, const std::string& server)
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
    ec = nabto_device_create_private_key(device, &str);
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

    /**
     * WARNING:
     *
     * nabto_device_close should be called before free. We don't here
     * to show that nabto does not cause leaks or hanging threads to
     * skip nabto_device_close(). Note that outstanding
     * NabtoDeviceFutures may not be resolved.
     */
    nabto_device_stop(device);
    nabto_device_free(device);

    return true;
}

NabtoDeviceListener* listener;
NabtoDeviceFuture* listenerFuture;
bool closing = false;

void run_stream_echo(const std::string& configFile, const std::string& logLevel)
{
    NabtoDeviceError ec;
    json config;
    if (!json_config_load(configFile, config)) {
        std::cerr << "The config file " << configFile << " does not exists, run with --init to create the config file" << std::endl;
        exit(-1);
    }
    head.next = NULL;
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

    ec = nabto_device_set_log_level(device, logLevel.c_str());
    if (ec) {
        std::cerr << "Failed to set loglevel" << std::endl;
    }
    ec = nabto_device_set_log_std_out_callback(device);
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

    listener = nabto_device_listener_new(device);
    if (listener == NULL) {
        std::cerr << "could not listen for streams" << std::endl;
        return;
    }
    ec = nabto_device_stream_init_listener(device, listener, 42);
    if (ec) {
        std::cerr << "could not init listener for streams" << std::endl;
        return;
    }
    listenerFuture = nabto_device_future_new(device);
    if (!listenerFuture) {
        std::cerr << "could not allocate future" << std::endl;
        return;
    }

    startListenForEchoStream(device);

    // Wait for the user to press Ctrl-C

    struct sigaction sigIntHandler;

    sigIntHandler.sa_handler = ctrlCHandler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;

    sigaction(SIGINT, &sigIntHandler, NULL);

    pause();
    closing = true;

    /**
     * WARNING:
     *
     * nabto_device_close should be called before free. We don't here
     * to show that nabto does not cause leaks or hanging threads to
     * skip nabto_device_close(). Note that outstanding
     * NabtoDeviceFutures may not be resolved. Any outstanding futures
     * and listeners must be freed manually. Here we free the
     * listener, but assumes that the stream has been closed nicely by
     * the client before stopping. If the stream has not been closed
     * nicely, this program will leak memory here.
     */
    struct StreamEchoState* iterator = head.next;
    if (listener != NULL) {
        nabto_device_listener_stop(listener);
    }
    while (iterator != NULL) {
        struct StreamEchoState* current = iterator;
        iterator = iterator->next;
        nabto_device_stream_abort(current->stream);
    }
    // nabto_device_stop will block until all internal events are handled. Since nabto_device_listener_stop and nabto_device_stream_abort has triggered events, these will be resolved before free actually occurs.

    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    nabto_device_close(device, fut);
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);

    nabto_device_stop(device);
    nabto_device_future_free(listenerFuture);
    nabto_device_listener_free(listener);
    nabto_device_free(device);
    return;
}

void removeState(struct StreamEchoState* state) {
    nabto_device_stream_free(state->stream);
    struct StreamEchoState* iterator = &head;
    while(iterator->next != state) {
        iterator = iterator->next;
    }
    iterator->next = state->next;
    state->next = NULL;
    free(state);
}

NabtoDeviceError allow_anyone_to_connect(NabtoDeviceConnectionRef connectionReference, const char* action, void* attributes, size_t attributesLength, void* userData)
{
    return NABTO_DEVICE_EC_OK;
}

// handle echo streams
void startListenForEchoStream(NabtoDevice* device) {
    nabto_device_listener_new_stream(listener, listenerFuture, &head.stream);
    nabto_device_future_set_callback(listenerFuture, newEchoStream, device);
}

void newEchoStream(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }
    NabtoDevice* device = (NabtoDevice*)userData;
    struct StreamEchoState* state = (struct StreamEchoState*)calloc(1, sizeof(struct StreamEchoState));
    state->stream = head.stream;
    state->next = head.next;
    head.next = state;
    head.stream = NULL; // ready for next stream
    state->active = true;
    state->dev = device;
    NabtoDeviceFuture* acceptFuture = nabto_device_future_new(device);
    nabto_device_stream_accept(state->stream, acceptFuture);

    nabto_device_future_set_callback(acceptFuture, streamAccepted, state);

    // listen for next stream
    startListenForEchoStream(device);
}

void streamAccepted(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    nabto_device_future_free(future);
    struct StreamEchoState* state = (struct StreamEchoState*)userData;
    if (ec) {
        removeState(state);
        return;
    }
    startRead(state);
}

void startRead(struct StreamEchoState* state)
{
    NabtoDeviceFuture* readFuture = nabto_device_future_new(state->dev);
    nabto_device_stream_read_some(state->stream, readFuture, state->readBuffer, READ_BUFFER_SIZE, &state->readLength);
    nabto_device_future_set_callback(readFuture, hasRead, state);
}

void hasRead(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    nabto_device_future_free(future);
    struct StreamEchoState* state = (struct StreamEchoState*)userData;
    if (ec == NABTO_DEVICE_EC_EOF) {
        // make a nice shutdown
        std::cout << "Read reached EOF closing nicely" << std::endl;
        startClose(state);
        return;
    }
    if (ec != NABTO_DEVICE_EC_OK) {
        removeState(state);
        return;
    }
    startWrite(state);
}

void startWrite(struct StreamEchoState* state)
{
    NabtoDeviceFuture* writeFuture = nabto_device_future_new(state->dev);
    nabto_device_stream_write(state->stream, writeFuture, state->readBuffer, state->readLength);
    nabto_device_future_set_callback(writeFuture, wrote, state);
}

void wrote(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    nabto_device_future_free(future);
    struct StreamEchoState* state = (struct StreamEchoState*)userData;
    if (ec != NABTO_DEVICE_EC_OK) {
        // just free the stream, there's no hope for it.
        removeState(state);
        return;
    }
    startRead(state);
}

void startClose(struct StreamEchoState* state)
{
    NabtoDeviceFuture* closeFuture = nabto_device_future_new(state->dev);
    nabto_device_stream_close(state->stream, closeFuture);
    nabto_device_future_set_callback(closeFuture, closed, state);
}

void closed(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    nabto_device_future_free(future);
    struct StreamEchoState* state = (struct StreamEchoState*)userData;

    // ignore error code, just release the resources.
    removeState(state);
}
