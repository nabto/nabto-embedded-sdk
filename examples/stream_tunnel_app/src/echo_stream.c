#include "echo_stream.h"

#include <stdio.h>
#include <stdlib.h>

#if defined(WIN32)
#define NEWLINE "\r\n"
#else
#define NEWLINE "\n"
#endif

#define READ_BUFFER_SIZE 1024

struct StreamEchoState {
    NabtoDeviceStream* stream;
    uint8_t readBuffer[READ_BUFFER_SIZE];
    size_t readLength;
    struct StreamEchoState* next;
    bool active;
    NabtoDevice* dev;
    NabtoDeviceListener* listener;
    NabtoDeviceFuture* future;
};

struct StreamEchoState head;
static void streamAccepted(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void startRead(struct StreamEchoState* state);
static void hasRead(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void startWrite(struct StreamEchoState* state);
static void wrote(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void startClose(struct StreamEchoState* state);
static void closed(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData);
static void listen_for_stream();

void new_stream_callback(NabtoDeviceFuture* future, NabtoDeviceError ec, void* userData)
{
    if (ec != NABTO_DEVICE_EC_OK) {
        nabto_device_future_free(future);
        nabto_device_listener_free(head.listener);
        return;
    }
    struct StreamEchoState* state = (struct StreamEchoState*)calloc(1, sizeof(struct StreamEchoState));
    state->stream = head.stream;
    state->next = head.next;
    head.next = state;
    head.stream = NULL; // ready for next stream
    state->active = true;
    state->dev = head.dev;
    NabtoDeviceFuture* acceptFuture = nabto_device_future_new(head.dev);
    nabto_device_stream_accept(state->stream, acceptFuture);

    nabto_device_future_set_callback(acceptFuture, streamAccepted, state);
    listen_for_stream();
}
void listen_for_stream() {
    nabto_device_listener_new_stream(head.listener, head.future, &head.stream);
    nabto_device_future_set_callback(head.future, &new_stream_callback, NULL);
}


bool run_echo_stream(NabtoDevice* device)
{
    head.dev = device;
    if ((head.listener = nabto_device_listener_new(device)) == NULL ||
    nabto_device_stream_init_listener(device, head.listener, 42) != NABTO_DEVICE_EC_OK ||
    (head.future = nabto_device_future_new(device)) == NULL) {
        printf("Failed to initialize stream listener" NEWLINE);
        nabto_device_future_free(head.future);
        nabto_device_listener_free(head.listener);
        return false;
    }
    listen_for_stream();
    return true;
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
    (void)ec;
    nabto_device_future_free(future);
    struct StreamEchoState* state = (struct StreamEchoState*)userData;

    // ignore error code, just release the resources.
    removeState(state);
}
