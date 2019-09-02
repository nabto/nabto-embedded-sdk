#ifndef NABTO_DEVICE_STREAM_H
#define NABTO_DEVICE_STREAM_H

#include <nabto/nabto_device.h>
#include <api/nabto_api_future_queue.h>

#include <core/nc_device.h>

struct nabto_device_context;

struct nabto_device_stream {
    struct nc_stream_context* stream;
    struct nabto_device_future* acceptFut;
    struct nabto_device_future* readFut;

    struct nabto_device_future* writeFut;

    struct nabto_device_future* closeFut;
    struct nabto_device_context* dev;

    // coordinate freeing of this context which can both be initiated by the user and by the system
    bool readyToFree;
};

void nabto_device_stream_listener_callback(np_error_code ec, struct nc_stream_context* stream, void* data);


#endif // NABTO_DEVICE_STREAM_H
