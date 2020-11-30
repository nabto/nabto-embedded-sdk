#include <nabto/nabto_device.h>
#include <apps/common/string_file.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <signal.h>

const char* productId = "pr-vpjqpkfu";
const char* deviceId = "de-pxitdrkk";
const char* keyFile = "device.key";

#define READ_BUFFER_SIZE 1024

struct StreamEchoState {
    NabtoDeviceStream* stream;
    uint8_t readBuffer[READ_BUFFER_SIZE];
    size_t readLength;
    struct StreamEchoState* next;
    bool active;
    NabtoDevice* dev;
};

struct StreamEchoState head;

NabtoDevice* device;

bool start_device(NabtoDevice* device);
void handle_device_error(NabtoDevice* d, NabtoDeviceListener* l, char* msg);
static void streamAccepted(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void startRead(struct StreamEchoState* state);
static void hasRead(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void startWrite(struct StreamEchoState* state);
static void wrote(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void startClose(struct StreamEchoState* state);
static void closed(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);

void signal_handler(int s)
{
    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    nabto_device_close(device, fut);
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
    nabto_device_stop(device);
}

int main(int argc, char** argv)
{
    NabtoDeviceListener* listener;
    NabtoDeviceFuture* listenerFuture;
    NabtoDeviceError ec = NABTO_DEVICE_EC_OK;
    head.next = NULL;

    printf("Nabto Embedded SDK Version %s\n", nabto_device_version());

    if ((device = nabto_device_new()) == NULL ||
        !start_device(device)) {
        handle_device_error(device, NULL, "Failed to start device");
        return -1;
    }

    if ((listener = nabto_device_listener_new(device)) == NULL ||
        nabto_device_stream_init_listener(device, listener, 42) != NABTO_DEVICE_EC_OK ||
        (listenerFuture = nabto_device_future_new(device)) == NULL)
    {
        handle_device_error(device, listener, "Failed to listen for streams");
        return -1;
    }

    signal(SIGINT, &signal_handler);

    while (true) {
        nabto_device_listener_new_stream(listener, listenerFuture, &head.stream);
        ec = nabto_device_future_wait(listenerFuture);
        if (ec != NABTO_DEVICE_EC_OK) {
            break;
        }
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
    }

    nabto_device_future_free(listenerFuture);
    nabto_device_listener_free(listener);
    nabto_device_free(device);

    printf("Device cleaned up and closed\n");
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

void streamAccepted(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    nabto_device_future_free(future);
    struct StreamEchoState* state = (struct StreamEchoState*)userData;
    if (ec != NABTO_DEVICE_EC_OK) {
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
        printf("Read reached EOF closing nicely\n");
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


bool start_device(NabtoDevice* device)
{
    NabtoDeviceError ec;
    char* privateKey;
    char* fp;

    if (!string_file_exists(keyFile)) {
        if ((ec = nabto_device_create_private_key(device, &privateKey)) != NABTO_DEVICE_EC_OK) {
            printf("Failed to create private key, ec=%s\n", nabto_device_error_get_message(ec));
            return false;
        }
        if (!string_file_save(keyFile, privateKey)) {
            printf("Failed to persist private key to file: %s\n", keyFile);
            nabto_device_string_free(privateKey);
            return false;
        }
        nabto_device_string_free(privateKey);
    }

    if (!string_file_load(keyFile, &privateKey)) {
        printf("Failed to load private key from file: %s\n", keyFile);
        return false;
    }

    if ((ec = nabto_device_set_private_key(device, privateKey)) != NABTO_DEVICE_EC_OK) {
        printf("Failed to set private key, ec=%s\n", nabto_device_error_get_message(ec));
        return false;
    }
    free(privateKey);

    if (nabto_device_get_device_fingerprint(device, &fp) != NABTO_DEVICE_EC_OK) {
        return false;
    }

    printf("Device: %s.%s with fingerprint: [%s]\n", productId, deviceId, fp);
    nabto_device_string_free(fp);

    if (nabto_device_set_product_id(device, productId) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_device_id(device, deviceId) != NABTO_DEVICE_EC_OK ||
        nabto_device_enable_mdns(device) != NABTO_DEVICE_EC_OK ||
        nabto_device_set_log_std_out_callback(device) != NABTO_DEVICE_EC_OK)
    {
        return false;
    }

    NabtoDeviceFuture* fut = nabto_device_future_new(device);
    nabto_device_start(device, fut);

    ec = nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
    if (ec != NABTO_DEVICE_EC_OK) {
        printf("Failed to start device, ec=%s\n", nabto_device_error_get_message(ec));
        return false;
    }

    return true;
}

void handle_device_error(NabtoDevice* d, NabtoDeviceListener* l, char* msg)
{
    NabtoDeviceFuture* f = nabto_device_future_new(d);
    if (d) {
        nabto_device_close(d, f);
        nabto_device_future_wait(f);
        nabto_device_stop(d);
        nabto_device_free(d);
    }
    if (f) {
        nabto_device_future_free(f);
    }
    if (l) {
        nabto_device_listener_free(l);
    }
    printf("%s", msg);
}